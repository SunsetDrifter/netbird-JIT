package jit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// accountOps is the slice of account.Manager the grant service needs: the
// system-authorized backing-group membership primitive (Task 3) and the
// account-settings read used for the propagation precheck. Keeping it as a
// narrow interface avoids importing the account/server package (which would
// create an import cycle) and lets tests substitute a fake.
//
// account.Manager satisfies it; Task 9 wires the real implementation.
type accountOps interface {
	// ApplyJitAutoGroup adds (add=true) or removes (add=false) the single JIT
	// backing group from the user's auto_groups, mirroring the change onto the
	// user's peers when propagation is enabled. It is a dumb add/remove
	// primitive — callers own the cross-grant still-needed check before removal.
	ApplyJitAutoGroup(ctx context.Context, accountID, userID, groupID string, add bool) error
	// GetAccountSettings returns the account settings; the grant service reads
	// GroupsPropagationEnabled to gate approval (no point granting access that
	// will never reach peers).
	GetAccountSettings(ctx context.Context, accountID, userID string) (*types.Settings, error)
}

// labelToActivity maps a lifecycle audit-action label (the value returned by
// ActionForEdge) to the activity code emitted for that transition. It is the
// single source of truth for "which event does this status change emit",
// satisfying the hard requirement that every emitted event is derived from the
// edge label rather than hand-picked per call site.
//
// Only edges that have a user-facing activity code appear here:
//   - grant.activate (approved/failed → active) is an internal completion step
//     of approve/extend/retry and emits no event of its own.
//   - grant.fail     (… → failed) is an internal fail-closed step (no event).
//
// grant.supersede maps to JitAccessExtended: a grant is only ever superseded by
// an extension/renewal, so the supersede edge is the defining event of an
// extend. The renewal's own approve+activate edges are emitted silently so an
// extend yields exactly one JitAccessExtended (and an approve exactly one
// JitAccessApproved).
var labelToActivity = map[string]activity.Activity{
	"grant.approve":   activity.JitAccessApproved,
	"grant.deny":      activity.JitAccessDenied,
	"grant.cancel":    activity.JitAccessCancelled,
	"grant.revoke":    activity.JitAccessRevoked,
	"grant.expire":    activity.JitAccessExpired,
	"grant.supersede": activity.JitAccessExtended,
}

// ptr returns a pointer to v (helper for the optional patch/stamp fields).
func ptr[T any](v T) *T { return &v }

// nowUTC is the clock used for all timestamps; a var so tests could override it
// if needed (the current tests assert relative windows, so they don't).
var nowUTC = func() time.Time { return time.Now().UTC() }

// ---------------------------------------------------------------------------
// internal transition helpers
// ---------------------------------------------------------------------------

// transition runs jit.Transition and, on success, emits the activity event the
// from→to edge maps to (if any). The emitted event's initiator is the actor
// (empty for system/scheduler actions), the target is the grant ID. A lost CAS
// (ErrTransitionConflict) and an illegal edge propagate to the caller unchanged.
func (m *Manager) transition(
	ctx context.Context,
	accountID string,
	grant *types.JitGrant,
	to types.GrantStatus,
	patch types.JitGrantPatch,
	actor Caller,
) (*types.JitGrant, error) {
	from := grant.Status
	updated, err := Transition(ctx, m.store, grant, to, patch)
	if err != nil {
		return nil, err
	}
	m.emitForEdge(ctx, accountID, updated, from, to, actor)
	return updated, nil
}

// transitionSilent runs jit.Transition without emitting any activity event. It
// is used for internal/secondary transitions whose public event is emitted by
// the enclosing operation (e.g. the approved→active activation, the prior-grant
// supersede during a renewal-approve, and the failed→failed retry re-stamp).
func (m *Manager) transitionSilent(
	ctx context.Context,
	grant *types.JitGrant,
	to types.GrantStatus,
	patch types.JitGrantPatch,
) (*types.JitGrant, error) {
	return Transition(ctx, m.store, grant, to, patch)
}

// emitForEdge emits the activity event mapped from the from→to edge label, if
// the edge has one. Unmapped edges (activate/fail) emit nothing.
func (m *Manager) emitForEdge(ctx context.Context, accountID string, grant *types.JitGrant, from, to types.GrantStatus, actor Caller) {
	label, ok := ActionForEdge(from, to)
	if !ok {
		return
	}
	code, ok := labelToActivity[label]
	if !ok {
		return
	}
	m.events.StoreEvent(ctx, actor.UserID, grant.ID, accountID, code, map[string]any{
		"policyId": grant.PolicyID,
		"action":   label,
	})
}

// activate adds the backing group then transitions the grant to active (or, on
// a membership-apply failure, to failed — fail-closed). Shared by Approve,
// ExtendByAdmin, and RetryFailed.
//
// On success it also retires a superseded predecessor (continuity: the backing
// group is never removed — this grant now holds it). The predecessor retire is
// opportunistic: only if it is still active (an admin extend may already have
// claimed it), and a lost CAS there is a benign skip.
func (m *Manager) activate(ctx context.Context, accountID string, policy *types.JitPolicy, grantID string, actor Caller) (*types.JitGrant, error) {
	if policy.BackingGroupID == "" {
		return nil, status.Errorf(status.PreconditionFailed, "jit: policy %s is not provisioned", policy.ID)
	}

	grant, err := m.store.GetJitGrantByID(ctx, accountID, grantID)
	if err != nil {
		return nil, err
	}

	if applyErr := m.account.ApplyJitAutoGroup(ctx, accountID, grant.RequesterUserID, policy.BackingGroupID, true); applyErr != nil {
		// Only the membership write can fail here. Mark the grant failed
		// (approved→failed, or failed→failed on a retry) and let the scheduler
		// retry; return the original error so the caller fails closed.
		if _, ferr := m.transitionSilent(ctx, grant, types.GrantStatusFailed, types.JitGrantPatch{
			LastError: ptr(applyErr.Error()),
		}); ferr != nil {
			return nil, fmt.Errorf("jit: mark grant %s failed after apply error (%w): %w", grantID, applyErr, ferr)
		}
		return nil, applyErr
	}

	started := nowUTC()
	expiresAt := started.Add(time.Duration(grant.RequestedDurationMinutes) * time.Minute)
	active, err := m.transitionSilent(ctx, grant, types.GrantStatusActive, types.JitGrantPatch{
		ActivatedAt: ptr(started),
		ExpiresAt:   ptr(expiresAt),
		LastError:   ptr(""),
	})
	if err != nil {
		return nil, fmt.Errorf("jit: activate grant %s: %w", grantID, err)
	}

	m.retirePredecessor(ctx, accountID, active, actor)
	return active, nil
}

// retirePredecessor opportunistically supersedes the grant this one renews,
// WITHOUT removing the backing group (continuity). A missing/non-active
// predecessor or a lost CAS is a benign skip; the supersede is emitted silently
// here (the enclosing extend/approve owns the public event).
func (m *Manager) retirePredecessor(ctx context.Context, accountID string, active *types.JitGrant, actor Caller) {
	if active.SupersedesGrantID == nil {
		return
	}
	prior, err := m.store.GetJitGrantByID(ctx, accountID, *active.SupersedesGrantID)
	if err != nil || prior == nil || prior.Status != types.GrantStatusActive {
		return
	}
	_, _ = m.transitionSilent(ctx, prior, types.GrantStatusSuperseded, types.JitGrantPatch{
		RevokedAt:    ptr(nowUTC()),
		RevokeReason: ptr("superseded_by_renewal"),
	})
}

// deactivate removes the backing group (subject to GATE-T7a) then transitions
// the grant to a terminal status, emitting the edge's event. Shared by
// EndEarly/Revoke/Expire and the active-grant path of TerminateGrantsForPolicy.
func (m *Manager) deactivate(
	ctx context.Context,
	accountID string,
	grant *types.JitGrant,
	terminal types.GrantStatus,
	reason string,
	actor Caller,
	forceRemove bool,
) (*types.JitGrant, error) {
	if err := m.removeMembership(ctx, accountID, grant, forceRemove); err != nil {
		return nil, err
	}
	updated, err := m.transition(ctx, accountID, grant, terminal, types.JitGrantPatch{
		RevokedAt:    ptr(nowUTC()),
		RevokeReason: ptr(reason),
	}, actor)
	if err != nil {
		// A lost CAS means a concurrent expire/revoke already finalized it.
		// Membership removal is idempotent, so report the current state.
		if errors.Is(err, ErrTransitionConflict) {
			return m.store.GetJitGrantByID(ctx, accountID, grant.ID)
		}
		return nil, err
	}
	return updated, nil
}

// removeMembership removes the backing group for grant unless GATE-T7a applies.
//
// GATE-T7a (cross-grant still-needed check): ApplyJitAutoGroup is a dumb
// remove. Before removing, verify NO OTHER active grant for the SAME user maps
// to the SAME backing group; if one does, skip the removal so we never strip
// access another active grant still relies on. forceRemove bypasses the gate —
// used only by the policy-teardown path, where the whole group is going away.
func (m *Manager) removeMembership(ctx context.Context, accountID string, grant *types.JitGrant, forceRemove bool) error {
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, grant.PolicyID)
	if err != nil {
		// Policy already gone (e.g. mid-teardown). Nothing to map a group from.
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if policy.BackingGroupID == "" {
		return nil
	}

	if !forceRemove {
		stillNeeded, err := m.groupStillNeeded(ctx, accountID, grant.RequesterUserID, policy.BackingGroupID, grant.ID)
		if err != nil {
			return err
		}
		if stillNeeded {
			return nil // another active grant relies on this group — keep it
		}
	}

	return m.account.ApplyJitAutoGroup(ctx, accountID, grant.RequesterUserID, policy.BackingGroupID, false)
}

// groupStillNeeded reports whether some active grant — other than excludeGrantID
// — for the same user maps to backingGroupID. Ports the excludeGrantId logic
// from the sidecar's membership.remove.
func (m *Manager) groupStillNeeded(ctx context.Context, accountID, userID, backingGroupID, excludeGrantID string) (bool, error) {
	grants, err := m.store.ListJitGrantsByRequester(ctx, accountID, userID)
	if err != nil {
		return false, err
	}
	for _, g := range grants {
		if g.ID == excludeGrantID || g.Status != types.GrantStatusActive {
			continue
		}
		policy, err := m.store.GetJitPolicyByID(ctx, accountID, g.PolicyID)
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return false, err
		}
		if policy.BackingGroupID == backingGroupID {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// public operations
// ---------------------------------------------------------------------------

// RequestAccess creates a pending JIT grant after eligibility, duration and
// in-flight checks. When the caller already holds an active grant for the
// policy the new grant is a renewal: its SupersedesGrantID points at the active
// grant, which is retired when the renewal activates. Emits JitAccessRequested
// (creation is not a status transition, so it is emitted directly here).
func (m *Manager) RequestAccess(
	ctx context.Context,
	accountID string,
	caller Caller,
	policyID string,
	durationMinutes int,
	justification string,
) (*types.JitGrant, error) {
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, policyID)
	if err != nil {
		return nil, err
	}
	if !policy.Enabled {
		return nil, status.Errorf(status.PreconditionFailed, "jit: policy %s is not available", policyID)
	}
	if !IsEligible(caller, policy.RequestableBy) {
		return nil, status.Errorf(status.PermissionDenied, "jit: you are not eligible to request this access")
	}
	if durationMinutes > policy.MaxDurationMinutes {
		return nil, status.Errorf(status.InvalidArgument,
			"jit: requested duration exceeds the maximum of %d minutes", policy.MaxDurationMinutes)
	}

	inFlight, err := m.hasInFlightRequest(ctx, accountID, caller.UserID, policyID)
	if err != nil {
		return nil, err
	}
	if inFlight {
		return nil, status.Errorf(status.PreconditionFailed,
			"jit: you already have a request awaiting a decision for this policy")
	}

	// An active grant means this is an extension/renewal.
	active, err := m.store.GetActiveJitGrantFor(ctx, accountID, caller.UserID, policyID)
	if err != nil {
		return nil, err
	}

	now := nowUTC()
	pendingExpiresAt := now.Add(time.Duration(policy.PendingTTLMinutes) * time.Minute)
	grant := &types.JitGrant{
		ID:                       xid.New().String(),
		AccountID:                accountID,
		PolicyID:                 policyID,
		RequesterUserID:          caller.UserID,
		RequesterEmail:           caller.Email,
		RequestedDurationMinutes: durationMinutes,
		Justification:            justification,
		Status:                   types.GrantStatusPending,
		RequestedAt:              now,
		PendingExpiresAt:         &pendingExpiresAt,
	}
	if active != nil {
		grant.SupersedesGrantID = ptr(active.ID)
	}

	if err := m.store.CreateJitGrant(ctx, grant); err != nil {
		return nil, fmt.Errorf("jit: create grant: %w", err)
	}

	m.events.StoreEvent(ctx, caller.UserID, grant.ID, accountID, activity.JitAccessRequested, map[string]any{
		"policyId":        policyID,
		"durationMinutes": durationMinutes,
		"extension":       active != nil,
	})
	return grant, nil
}

// hasInFlightRequest reports whether the user already has a pending or approved
// (undecided / in-progress) grant for the policy. The Go store has no dedicated
// count query, so this filters the requester's grants in memory — equivalent to
// the sidecar's countUndecided.
func (m *Manager) hasInFlightRequest(ctx context.Context, accountID, userID, policyID string) (bool, error) {
	grants, err := m.store.ListJitGrantsByRequester(ctx, accountID, userID)
	if err != nil {
		return false, err
	}
	for _, g := range grants {
		if g.PolicyID != policyID {
			continue
		}
		if g.Status == types.GrantStatusPending || g.Status == types.GrantStatusApproved {
			return true, nil
		}
	}
	return false, nil
}

// ListMine returns the caller's own grants, optionally filtered to a single
// status. Account-scoped via the store.
func (m *Manager) ListMine(ctx context.Context, accountID string, caller Caller, status *types.GrantStatus) ([]*types.JitGrant, error) {
	grants, err := m.store.ListJitGrantsByRequester(ctx, accountID, caller.UserID)
	if err != nil {
		return nil, err
	}
	if status == nil {
		return grants, nil
	}
	filtered := make([]*types.JitGrant, 0, len(grants))
	for _, g := range grants {
		if g.Status == *status {
			filtered = append(filtered, g)
		}
	}
	return filtered, nil
}

// Approve approves a pending request and activates it: it claims pending→approved
// atomically (so two concurrent approvals can't both reach activation), then
// adds the backing group and transitions approved→active with
// ExpiresAt = approvalTime + RequestedDurationMinutes. A renewal additionally
// retires the prior active grant to superseded without dropping membership.
//
// Guards: the caller must satisfy the policy's approver criteria, may not
// approve their own request (unless allowSelfApproval), and the account's group
// propagation must be enabled (no point granting access that won't reach peers
// — checked BEFORE the claim so a propagation-off approval leaves the grant
// pending and never touches membership). Fail-closed: a membership-apply
// failure transitions approved→failed and returns the error.
func (m *Manager) Approve(ctx context.Context, accountID string, caller Caller, grantID string) (*types.JitGrant, error) {
	grant, err := m.store.GetJitGrantByID(ctx, accountID, grantID)
	if err != nil {
		return nil, err
	}
	if grant.Status != types.GrantStatusPending {
		return nil, status.Errorf(status.PreconditionFailed, "jit: request is %s, not pending", grant.Status)
	}
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, grant.PolicyID)
	if err != nil {
		return nil, err
	}
	if !CanApprove(caller, policy.ApproverCriteria) {
		return nil, status.Errorf(status.PermissionDenied, "jit: not permitted to approve this request")
	}
	if !m.allowSelfApproval && grant.RequesterUserID == caller.UserID {
		return nil, status.Errorf(status.PermissionDenied, "jit: you cannot approve your own request")
	}

	// Propagation precheck (before the claim): a disabled propagation setting
	// means a grant would never reach peers, so refuse and leave the request
	// pending without touching membership.
	enabled, err := m.propagationEnabled(ctx, accountID, caller.UserID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, status.Errorf(status.PreconditionFailed,
			"jit: account setting groups_propagation_enabled is off; grants would not reach peers")
	}

	// Atomic pending→approved so concurrent approvals can't both activate.
	approved, err := m.transition(ctx, accountID, grant, types.GrantStatusApproved, types.JitGrantPatch{
		ApproverUserID: ptr(caller.UserID),
		ApproverEmail:  ptr(caller.Email),
		DecidedAt:      ptr(nowUTC()),
	}, caller)
	if err != nil {
		return nil, err
	}

	return m.activate(ctx, accountID, policy, approved.ID, caller)
}

// Deny denies a pending request (pending→denied). Approver-gated. Emits
// JitAccessDenied.
func (m *Manager) Deny(ctx context.Context, accountID string, caller Caller, grantID, reason string) (*types.JitGrant, error) {
	grant, err := m.store.GetJitGrantByID(ctx, accountID, grantID)
	if err != nil {
		return nil, err
	}
	if grant.Status != types.GrantStatusPending {
		return nil, status.Errorf(status.PreconditionFailed, "jit: request is %s, not pending", grant.Status)
	}
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, grant.PolicyID)
	if err != nil {
		return nil, err
	}
	if !CanApprove(caller, policy.ApproverCriteria) {
		return nil, status.Errorf(status.PermissionDenied, "jit: not permitted to decide this request")
	}
	return m.transition(ctx, accountID, grant, types.GrantStatusDenied, types.JitGrantPatch{
		ApproverUserID: ptr(caller.UserID),
		ApproverEmail:  ptr(caller.Email),
		DecidedAt:      ptr(nowUTC()),
		DenialReason:   ptr(reason),
	}, caller)
}

// Cancel lets the requester withdraw their own pending request
// (pending→cancelled). Requester-only. Emits JitAccessCancelled.
func (m *Manager) Cancel(ctx context.Context, accountID string, caller Caller, grantID string) (*types.JitGrant, error) {
	grant, err := m.store.GetJitGrantByID(ctx, accountID, grantID)
	if err != nil {
		return nil, err
	}
	if grant.RequesterUserID != caller.UserID {
		return nil, status.Errorf(status.PermissionDenied, "jit: only the requester may cancel this request")
	}
	if grant.Status != types.GrantStatusPending {
		return nil, status.Errorf(status.PreconditionFailed, "jit: only pending requests can be cancelled")
	}
	return m.transition(ctx, accountID, grant, types.GrantStatusCancelled, types.JitGrantPatch{
		DecidedAt:    ptr(nowUTC()),
		DenialReason: ptr("cancelled_by_requester"),
	}, caller)
}

// EndEarly lets the requester end their own active grant (active→revoked),
// removing the backing group (subject to GATE-T7a). Requester-only. Emits
// JitAccessRevoked.
func (m *Manager) EndEarly(ctx context.Context, accountID string, caller Caller, grantID string) (*types.JitGrant, error) {
	grant, err := m.store.GetJitGrantByID(ctx, accountID, grantID)
	if err != nil {
		return nil, err
	}
	if grant.RequesterUserID != caller.UserID {
		return nil, status.Errorf(status.PermissionDenied, "jit: only the requester may end this grant")
	}
	if grant.Status != types.GrantStatusActive {
		return nil, status.Errorf(status.PreconditionFailed, "jit: only active grants can be ended")
	}
	return m.deactivate(ctx, accountID, grant, types.GrantStatusRevoked, "ended_by_user", caller, false)
}

// Revoke lets an admin/approver revoke an active or failed grant
// (active|failed→revoked), removing the backing group (subject to GATE-T7a).
// Emits JitAccessRevoked.
func (m *Manager) Revoke(ctx context.Context, accountID string, caller Caller, grantID, reason string) (*types.JitGrant, error) {
	grant, err := m.store.GetJitGrantByID(ctx, accountID, grantID)
	if err != nil {
		return nil, err
	}
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, grant.PolicyID)
	if err != nil {
		return nil, err
	}
	if !CanApprove(caller, policy.ApproverCriteria) {
		return nil, status.Errorf(status.PermissionDenied, "jit: not permitted to revoke this grant")
	}
	if grant.Status != types.GrantStatusActive && grant.Status != types.GrantStatusFailed {
		return nil, status.Errorf(status.PreconditionFailed, "jit: cannot revoke a %s grant", grant.Status)
	}
	if reason == "" {
		reason = "manual"
	}
	return m.deactivate(ctx, accountID, grant, types.GrantStatusRevoked, reason, caller, false)
}

// ExtendByAdmin renews an active grant directly (no pending step). It atomically
// claims the target (active→superseded) FIRST so two concurrent extends can't
// both create an active renewal — the loser's claim CAS fails. The winner
// creates a renewal grant (born approved), then activates it; the backing group
// is never dropped (the renewal holds the same group → continuity). ExpiresAt =
// now + durationMinutes (capped at the policy max). Approver-gated. Emits
// JitAccessExtended (on the supersede-claim edge). Fail-closed if activation
// fails.
func (m *Manager) ExtendByAdmin(ctx context.Context, accountID string, caller Caller, grantID string, durationMinutes int) (*types.JitGrant, error) {
	target, err := m.store.GetJitGrantByID(ctx, accountID, grantID)
	if err != nil {
		return nil, err
	}
	if target.Status != types.GrantStatusActive {
		return nil, status.Errorf(status.PreconditionFailed, "jit: only active grants can be extended")
	}
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, target.PolicyID)
	if err != nil {
		return nil, err
	}
	if !CanApprove(caller, policy.ApproverCriteria) {
		return nil, status.Errorf(status.PermissionDenied, "jit: not permitted to extend this grant")
	}
	if durationMinutes > policy.MaxDurationMinutes {
		return nil, status.Errorf(status.InvalidArgument,
			"jit: requested duration exceeds the maximum of %d minutes", policy.MaxDurationMinutes)
	}

	// Claim the target first. Concurrent extends race on this CAS; the loser
	// gets ErrTransitionConflict → conflict, so only one renewal is created.
	// This emits JitAccessExtended (grant.supersede → Extended).
	if _, err := m.transition(ctx, accountID, target, types.GrantStatusSuperseded, types.JitGrantPatch{
		RevokedAt:    ptr(nowUTC()),
		RevokeReason: ptr("superseded_by_renewal"),
	}, caller); err != nil {
		if errors.Is(err, ErrTransitionConflict) {
			return nil, status.Errorf(status.PreconditionFailed,
				"jit: grant is already being renewed or is no longer active")
		}
		return nil, err
	}

	now := nowUTC()
	renewal := &types.JitGrant{
		ID:                       xid.New().String(),
		AccountID:                accountID,
		PolicyID:                 target.PolicyID,
		SupersedesGrantID:        ptr(target.ID),
		RequesterUserID:          target.RequesterUserID,
		RequesterEmail:           target.RequesterEmail,
		RequestedDurationMinutes: durationMinutes,
		Status:                   types.GrantStatusApproved,
		RequestedAt:              now,
		ApproverUserID:           ptr(caller.UserID),
		ApproverEmail:            ptr(caller.Email),
		DecidedAt:                ptr(now),
	}
	if err := m.store.CreateJitGrant(ctx, renewal); err != nil {
		return nil, fmt.Errorf("jit: create renewal grant: %w", err)
	}

	// activate re-reads the renewal; its predecessor-retire no-ops (target is
	// already superseded). Emits nothing (the extend's event was the claim).
	return m.activate(ctx, accountID, policy, renewal.ID, caller)
}

// TerminateGrantsForPolicy implements the grantCanceller seam DeletePolicy
// needs: every active|failed grant for the policy is revoked (membership
// removed) and every pending|approved grant is cancelled (no membership to
// remove). Removing the backing group for ALL active grants is correct here —
// the whole policy/group is being torn down — so the GATE-T7a still-needed
// check is bypassed (forceRemove). Without cancelling the undecided grants,
// approve would later 409 on the missing policy and they would linger.
func (m *Manager) TerminateGrantsForPolicy(ctx context.Context, accountID, policyID, reason string) error {
	// Empty status → all grants for the account; filter to this policy.
	grants, err := m.store.ListJitGrantsByAccount(ctx, accountID, "")
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.PolicyID != policyID {
			continue
		}
		switch grant.Status {
		case types.GrantStatusActive, types.GrantStatusFailed:
			if _, err := m.deactivate(ctx, accountID, grant, types.GrantStatusRevoked, reason, Caller{}, true); err != nil {
				return fmt.Errorf("jit: revoke grant %s during policy teardown: %w", grant.ID, err)
			}
		case types.GrantStatusPending, types.GrantStatusApproved:
			if _, err := m.transition(ctx, accountID, grant, types.GrantStatusCancelled, types.JitGrantPatch{
				DecidedAt:    ptr(nowUTC()),
				DenialReason: ptr(reason),
			}, Caller{}); err != nil && !errors.Is(err, ErrTransitionConflict) {
				return fmt.Errorf("jit: cancel grant %s during policy teardown: %w", grant.ID, err)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// scheduler hooks (Task 8 drives these)
// ---------------------------------------------------------------------------

// Expire ends an active grant whose clock has run out (active→expired),
// removing the backing group (subject to GATE-T7a). Emits JitAccessExpired.
func (m *Manager) Expire(ctx context.Context, grant *types.JitGrant) (*types.JitGrant, error) {
	return m.deactivate(ctx, grant.AccountID, grant, types.GrantStatusExpired, "expired", Caller{}, false)
}

// AutoDenyPending denies a pending request that outlived its pending TTL
// (pending→denied). Emits JitAccessDenied.
func (m *Manager) AutoDenyPending(ctx context.Context, grant *types.JitGrant) (*types.JitGrant, error) {
	updated, err := m.transition(ctx, grant.AccountID, grant, types.GrantStatusDenied, types.JitGrantPatch{
		DecidedAt:    ptr(nowUTC()),
		DenialReason: ptr("request_timed_out"),
	}, Caller{})
	if err != nil && errors.Is(err, ErrTransitionConflict) {
		// Already decided by a concurrent actor — benign.
		return m.store.GetJitGrantByID(ctx, grant.AccountID, grant.ID)
	}
	return updated, err
}

// RetryFailed re-attempts activation of a failed grant (failed→active, or
// failed→failed on another failure). Used by the scheduler to recover grants
// whose membership write failed at approval time.
func (m *Manager) RetryFailed(ctx context.Context, grant *types.JitGrant) error {
	policy, err := m.store.GetJitPolicyByID(ctx, grant.AccountID, grant.PolicyID)
	if err != nil {
		if isNotFound(err) {
			return nil // policy gone — nothing to retry
		}
		return err
	}
	if policy.BackingGroupID == "" {
		return nil
	}
	_, err = m.activate(ctx, grant.AccountID, policy, grant.ID, Caller{})
	return err
}

// propagationEnabled reads the account settings and returns
// GroupsPropagationEnabled.
func (m *Manager) propagationEnabled(ctx context.Context, accountID, userID string) (bool, error) {
	settings, err := m.account.GetAccountSettings(ctx, accountID, userID)
	if err != nil {
		return false, fmt.Errorf("jit: read account settings: %w", err)
	}
	return settings.GroupsPropagationEnabled, nil
}
