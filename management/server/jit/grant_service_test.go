package jit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ---------------------------------------------------------------------------
// Fake accountOps (Task 3 ApplyJitAutoGroup + propagation settings read)
// ---------------------------------------------------------------------------

type membershipCall struct {
	userID  string
	groupID string
	add     bool
}

// fakeAccount is an in-memory implementation of jit's accountOps interface.
// It records every ApplyJitAutoGroup call and reports a configurable
// propagation setting. applyErr (when set) makes ApplyJitAutoGroup fail so the
// fail-closed path can be exercised.
type fakeAccount struct {
	mu sync.Mutex

	propagation bool
	applyErr    error
	settingsErr error

	calls []membershipCall
}

func newFakeAccount() *fakeAccount {
	return &fakeAccount{propagation: true}
}

func (f *fakeAccount) ApplyJitAutoGroup(_ context.Context, _, userID, groupID string, add bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, membershipCall{userID, groupID, add})
	return f.applyErr
}

func (f *fakeAccount) GetAccountSettings(_ context.Context, _, _ string) (*types.Settings, error) {
	if f.settingsErr != nil {
		return nil, f.settingsErr
	}
	return &types.Settings{GroupsPropagationEnabled: f.propagation}, nil
}

func (f *fakeAccount) addRemoveCalls() (adds, removes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.add {
			adds++
		} else {
			removes++
		}
	}
	return adds, removes
}

// ---------------------------------------------------------------------------
// Test manager wired with grant-service dependencies
// ---------------------------------------------------------------------------

func newGrantTestManager(t *testing.T) (*jit.Manager, *fakeStore, *fakeAccount, *fakeEvents) {
	t.Helper()
	store := newFakeStore()
	prov := newFakeProvisioner()
	events := &fakeEvents{}
	account := newFakeAccount()
	// grants==nil → manager self-wires as its own grant canceller (TerminateGrantsForPolicy).
	m := jit.NewManager(store, prov, events, account, nil, jit.DefaultMarker, 1440)
	return m, store, account, events
}

// seedPolicy persists a provisioned JIT policy directly into the fake store so
// grant operations have a backing group to add/remove.
func seedGrantPolicy(t *testing.T, store *fakeStore) *types.JitPolicy {
	t.Helper()
	p := &types.JitPolicy{
		ID:                 "pol-1",
		AccountID:          testAccountID,
		Name:               "Prod",
		TargetResourceIDs:  []string{"r1"},
		Traffic:            types.JitTraffic{Protocol: "all"},
		MaxDurationMinutes: 120,
		RequestableBy:      types.JitRequestableBy{Mode: "groups", GroupIDs: []string{"eng"}},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
		PendingTTLMinutes:  1440,
		BackingGroupID:     "g1",
		NetbirdPolicyID:    "np1",
		Enabled:            true,
	}
	if err := store.SaveJitPolicy(context.Background(), p); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	return p
}

var (
	requester = jit.Caller{UserID: "u1", Email: "u1@x.com", IsAdmin: false, Groups: []string{"eng"}}
	admin     = jit.Caller{UserID: "adm", Email: "a@x.com", IsAdmin: true, Groups: nil}
)

const fixedNowRFC = "2026-06-26T12:00:00Z"

func ctx() context.Context { return context.Background() }

// ---------------------------------------------------------------------------
// RequestAccess
// ---------------------------------------------------------------------------

func TestRequestAccess_HappyPathEmitsRequested(t *testing.T) {
	m, store, _, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)

	g, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "need it")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if g.Status != types.GrantStatusPending {
		t.Errorf("status = %q, want pending", g.Status)
	}
	if g.RequesterUserID != requester.UserID {
		t.Errorf("requester = %q, want %q", g.RequesterUserID, requester.UserID)
	}
	if g.RequestedDurationMinutes != 60 {
		t.Errorf("duration = %d, want 60", g.RequestedDurationMinutes)
	}
	if g.PendingExpiresAt == nil {
		t.Error("expected PendingExpiresAt to be set from policy TTL")
	}
	if g.SupersedesGrantID != nil {
		t.Errorf("first request should not supersede anything, got %v", *g.SupersedesGrantID)
	}
	ev := events.only()
	if ev.activity != activity.JitAccessRequested {
		t.Errorf("activity = %v, want JitAccessRequested", ev.activity)
	}
	if ev.targetID != g.ID || ev.initiatorID != requester.UserID || ev.accountID != testAccountID {
		t.Errorf("event scoping wrong: %+v", ev)
	}
}

func TestRequestAccess_IneligibleRejected(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)

	other := jit.Caller{UserID: "u9", Groups: []string{"sales"}}
	_, err := m.RequestAccess(ctx(), testAccountID, other, p.ID, 60, "")
	if err == nil {
		t.Fatal("expected ineligible requester to be rejected")
	}
	if !isStatusType(err, status.PermissionDenied) {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

func TestRequestAccess_EligibleViaModeAll(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	// Switch the policy to mode=all so any caller is eligible.
	p.RequestableBy = types.JitRequestableBy{Mode: "all"}
	if err := store.SaveJitPolicy(ctx(), p); err != nil {
		t.Fatal(err)
	}

	other := jit.Caller{UserID: "u9", Groups: []string{"sales"}}
	if _, err := m.RequestAccess(ctx(), testAccountID, other, p.ID, 60, ""); err != nil {
		t.Fatalf("mode=all should allow any caller: %v", err)
	}
}

func TestRequestAccess_DurationOverMaxRejected(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)

	_, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 999, "")
	if err == nil {
		t.Fatal("expected duration > max to be rejected")
	}
	if !isStatusType(err, status.InvalidArgument) {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

func TestRequestAccess_DuplicateInFlightRejected(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)

	if _, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, ""); err != nil {
		t.Fatalf("first request: %v", err)
	}
	_, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if err == nil {
		t.Fatal("expected a second in-flight request to be rejected")
	}
	if !isStatusType(err, status.PreconditionFailed) && !isStatusType(err, status.AlreadyExists) {
		t.Errorf("want conflict-style error, got %v", err)
	}
}

func TestRequestAccess_RenewalDetectedSetsSupersedes(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)

	g1, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if err != nil {
		t.Fatalf("seed request: %v", err)
	}
	if _, err := m.Approve(ctx(), testAccountID, admin, g1.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// An extension request while g1 is active must set SupersedesGrantID.
	ext, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 90, "")
	if err != nil {
		t.Fatalf("extension request: %v", err)
	}
	if ext.SupersedesGrantID == nil || *ext.SupersedesGrantID != g1.ID {
		t.Errorf("extension SupersedesGrantID = %v, want %q", ext.SupersedesGrantID, g1.ID)
	}

	// A third (double extension) is blocked — ext is undecided.
	if _, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 30, ""); err == nil {
		t.Error("expected a double-extension to be rejected while ext is undecided")
	}
}

// ---------------------------------------------------------------------------
// Approve
// ---------------------------------------------------------------------------

func TestApprove_AddsGroupActivatesSetsExpiryEmitsApproved(t *testing.T) {
	m, store, account, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	events.events = nil

	active, err := m.Approve(ctx(), testAccountID, admin, g.ID)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if active.Status != types.GrantStatusActive {
		t.Errorf("status = %q, want active", active.Status)
	}
	if active.ActivatedAt == nil {
		t.Error("ActivatedAt not set")
	}
	if active.ExpiresAt == nil {
		t.Fatal("ExpiresAt not set")
	}
	// ExpiresAt = activation + duration. activation ≈ now; ExpiresAt-ActivatedAt == 60m.
	if d := active.ExpiresAt.Sub(*active.ActivatedAt); d != 60*time.Minute {
		t.Errorf("expiry window = %v, want 60m", d)
	}
	if active.ApproverUserID == nil || *active.ApproverUserID != admin.UserID {
		t.Errorf("approver = %v, want %q", active.ApproverUserID, admin.UserID)
	}

	// Backing group added exactly once for the requester.
	adds, removes := account.addRemoveCalls()
	if adds != 1 || removes != 0 {
		t.Errorf("membership adds=%d removes=%d, want 1/0", adds, removes)
	}
	if account.calls[0].groupID != p.BackingGroupID || account.calls[0].userID != requester.UserID {
		t.Errorf("membership call = %+v, want add %s to %s", account.calls[0], p.BackingGroupID, requester.UserID)
	}

	// JitAccessApproved emitted.
	if !hasActivity(events, activity.JitAccessApproved) {
		t.Errorf("expected JitAccessApproved; events=%v", activitiesOf(events))
	}
}

func TestApprove_SelfApprovalRejected(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	// Admin who is also the requester (and eligible).
	selfAdmin := jit.Caller{UserID: "adm", Email: "a@x.com", IsAdmin: true, Groups: []string{"eng"}}
	g, _ := m.RequestAccess(ctx(), testAccountID, selfAdmin, p.ID, 60, "")

	_, err := m.Approve(ctx(), testAccountID, selfAdmin, g.ID)
	if err == nil {
		t.Fatal("expected self-approval to be rejected")
	}
	if !isStatusType(err, status.PermissionDenied) {
		t.Errorf("want PermissionDenied, got %v", err)
	}
	if adds, _ := account.addRemoveCalls(); adds != 0 {
		t.Error("self-approval must not touch membership")
	}
}

func TestApprove_PropagationDisabledRejectedNoMembership(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	account.propagation = false
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")

	_, err := m.Approve(ctx(), testAccountID, admin, g.ID)
	if err == nil {
		t.Fatal("expected approval to be rejected when propagation is disabled")
	}
	if !isStatusType(err, status.PreconditionFailed) {
		t.Errorf("want PreconditionFailed (propagation), got %v", err)
	}
	// No membership applied; grant left pending (no active access created).
	if len(account.calls) != 0 {
		t.Errorf("propagation-off must not touch membership; calls=%v", account.calls)
	}
	got, _ := store.GetJitGrantByID(ctx(), testAccountID, g.ID)
	if got.Status != types.GrantStatusPending {
		t.Errorf("grant status = %q, want still pending", got.Status)
	}
}

func TestApprove_NonApproverRejected(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")

	// A non-admin caller (any_admin criteria) cannot approve.
	nonApprover := jit.Caller{UserID: "u2", IsAdmin: false, Groups: []string{"eng"}}
	if _, err := m.Approve(ctx(), testAccountID, nonApprover, g.ID); err == nil {
		t.Fatal("expected non-approver to be rejected")
	}
}

func TestApprove_GroupApproverAllowed(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	// Criteria = groups{approvers}; a non-admin in that group may approve.
	p.ApproverCriteria = types.JitApproverCriteria{Mode: "groups", GroupIDs: []string{"approvers"}}
	if err := store.SaveJitPolicy(ctx(), p); err != nil {
		t.Fatal(err)
	}
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")

	groupApprover := jit.Caller{UserID: "u2", IsAdmin: false, Groups: []string{"approvers"}}
	if _, err := m.Approve(ctx(), testAccountID, groupApprover, g.ID); err != nil {
		t.Fatalf("group approver should be allowed: %v", err)
	}
}

func TestApprove_ApplyFailsMarksFailedFailClosed(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	account.applyErr = errors.New("netbird unavailable")
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")

	_, err := m.Approve(ctx(), testAccountID, admin, g.ID)
	if err == nil {
		t.Fatal("expected apply failure to propagate")
	}
	got, _ := store.GetJitGrantByID(ctx(), testAccountID, g.ID)
	if got.Status != types.GrantStatusFailed {
		t.Errorf("grant status = %q, want failed (fail-closed)", got.Status)
	}
}

// ---------------------------------------------------------------------------
// Deny / Cancel / EndEarly / Revoke
// ---------------------------------------------------------------------------

func TestDeny_PendingToDeniedEmitsDenied(t *testing.T) {
	m, store, _, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	events.events = nil

	out, err := m.Deny(ctx(), testAccountID, admin, g.ID, "not now")
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if out.Status != types.GrantStatusDenied {
		t.Errorf("status = %q, want denied", out.Status)
	}
	if out.DenialReason == nil || *out.DenialReason != "not now" {
		t.Errorf("denial reason = %v, want 'not now'", out.DenialReason)
	}
	if !hasActivity(events, activity.JitAccessDenied) {
		t.Errorf("expected JitAccessDenied; got %v", activitiesOf(events))
	}
}

func TestDeny_NonApproverRejected(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")

	if _, err := m.Deny(ctx(), testAccountID, requester, g.ID, "x"); err == nil {
		t.Fatal("expected non-approver deny to be rejected")
	}
}

func TestCancel_RequesterOnlyEmitsCancelled(t *testing.T) {
	m, store, _, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	events.events = nil

	// A different user cannot cancel.
	other := jit.Caller{UserID: "u2"}
	if _, err := m.Cancel(ctx(), testAccountID, other, g.ID); err == nil {
		t.Fatal("expected non-requester cancel to be rejected")
	}

	out, err := m.Cancel(ctx(), testAccountID, requester, g.ID)
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if out.Status != types.GrantStatusCancelled {
		t.Errorf("status = %q, want cancelled", out.Status)
	}
	if !hasActivity(events, activity.JitAccessCancelled) {
		t.Errorf("expected JitAccessCancelled; got %v", activitiesOf(events))
	}
}

func TestEndEarly_RequesterRevokesAndRemovesMembership(t *testing.T) {
	m, store, account, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if _, err := m.Approve(ctx(), testAccountID, admin, g.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	account.calls = nil
	events.events = nil

	// Non-requester cannot end.
	if _, err := m.EndEarly(ctx(), testAccountID, jit.Caller{UserID: "u2"}, g.ID); err == nil {
		t.Fatal("expected non-requester EndEarly to be rejected")
	}

	out, err := m.EndEarly(ctx(), testAccountID, requester, g.ID)
	if err != nil {
		t.Fatalf("EndEarly: %v", err)
	}
	if out.Status != types.GrantStatusRevoked {
		t.Errorf("status = %q, want revoked", out.Status)
	}
	adds, removes := account.addRemoveCalls()
	if adds != 0 || removes != 1 {
		t.Errorf("membership adds=%d removes=%d, want 0/1", adds, removes)
	}
	if !hasActivity(events, activity.JitAccessRevoked) {
		t.Errorf("expected JitAccessRevoked; got %v", activitiesOf(events))
	}
}

func TestRevoke_AdminRevokesActiveRemovesMembership(t *testing.T) {
	m, store, account, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if _, err := m.Approve(ctx(), testAccountID, admin, g.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	account.calls = nil
	events.events = nil

	// Non-admin/approver cannot revoke.
	if _, err := m.Revoke(ctx(), testAccountID, jit.Caller{UserID: "u2"}, g.ID, "x"); err == nil {
		t.Fatal("expected non-admin revoke to be rejected")
	}

	out, err := m.Revoke(ctx(), testAccountID, admin, g.ID, "cleanup")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if out.Status != types.GrantStatusRevoked {
		t.Errorf("status = %q, want revoked", out.Status)
	}
	if _, removes := account.addRemoveCalls(); removes != 1 {
		t.Errorf("expected one membership removal, got %d", removes)
	}
	if !hasActivity(events, activity.JitAccessRevoked) {
		t.Errorf("expected JitAccessRevoked; got %v", activitiesOf(events))
	}
}

// ---------------------------------------------------------------------------
// GATE-T7a: cross-grant still-needed check
// ---------------------------------------------------------------------------

func TestGate_RevokeSkipsRemovalWhenAnotherActiveGrantNeedsGroup(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)

	// Two active grants for the SAME user on the SAME policy/backing group.
	// (Manufactured directly in the store: in practice the supersede rule
	// prevents two active grants per (user,policy), but the gate must be robust
	// to any second active grant mapping to the same group.)
	g1 := activeGrant(t, store, "ga", p.ID, requester.UserID)
	_ = activeGrant(t, store, "gb", p.ID, requester.UserID)
	account.calls = nil

	// Revoking g1 must NOT remove the group because gb still needs it.
	if _, err := m.Revoke(ctx(), testAccountID, admin, g1.ID, "manual"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, removes := account.addRemoveCalls(); removes != 0 {
		t.Errorf("expected NO membership removal (another active grant needs the group), got %d", removes)
	}
	// g1 is still finalized to revoked.
	got, _ := store.GetJitGrantByID(ctx(), testAccountID, g1.ID)
	if got.Status != types.GrantStatusRevoked {
		t.Errorf("g1 status = %q, want revoked", got.Status)
	}
}

func TestGate_ExpireRemovesGroupWhenNoOtherActiveGrant(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g := activeGrant(t, store, "ga", p.ID, requester.UserID)
	account.calls = nil

	if _, err := m.Expire(ctx(), g); err != nil {
		t.Fatalf("Expire: %v", err)
	}
	if _, removes := account.addRemoveCalls(); removes != 1 {
		t.Errorf("expected one membership removal (sole active grant), got %d", removes)
	}
	got, _ := store.GetJitGrantByID(ctx(), testAccountID, g.ID)
	if got.Status != types.GrantStatusExpired {
		t.Errorf("status = %q, want expired", got.Status)
	}
}

// ---------------------------------------------------------------------------
// Supersede continuity (renewal approve)
// ---------------------------------------------------------------------------

func TestApproveExtension_SupersedesPriorWithoutRemovingMembership(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g1, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if _, err := m.Approve(ctx(), testAccountID, admin, g1.ID); err != nil {
		t.Fatalf("approve g1: %v", err)
	}

	g2, err := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 120, "")
	if err != nil {
		t.Fatalf("extension request: %v", err)
	}
	if g2.SupersedesGrantID == nil || *g2.SupersedesGrantID != g1.ID {
		t.Fatalf("g2 must supersede g1")
	}
	account.calls = nil

	active2, err := m.Approve(ctx(), testAccountID, admin, g2.ID)
	if err != nil {
		t.Fatalf("approve g2: %v", err)
	}
	if active2.Status != types.GrantStatusActive {
		t.Errorf("g2 status = %q, want active", active2.Status)
	}
	// Prior grant retired to superseded.
	prior, _ := store.GetJitGrantByID(ctx(), testAccountID, g1.ID)
	if prior.Status != types.GrantStatusSuperseded {
		t.Errorf("g1 status = %q, want superseded", prior.Status)
	}
	// Membership NEVER removed during the renewal (continuity).
	if _, removes := account.addRemoveCalls(); removes != 0 {
		t.Errorf("renewal must NOT remove membership, got %d removals", removes)
	}
}

// ---------------------------------------------------------------------------
// ExtendByAdmin
// ---------------------------------------------------------------------------

func TestExtendByAdmin_AtomicSupersedeContinuousMembershipEmitsExtended(t *testing.T) {
	m, store, account, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g1, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if _, err := m.Approve(ctx(), testAccountID, admin, g1.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	account.calls = nil
	events.events = nil

	renewed, err := m.ExtendByAdmin(ctx(), testAccountID, admin, g1.ID, 120)
	if err != nil {
		t.Fatalf("ExtendByAdmin: %v", err)
	}
	if renewed.Status != types.GrantStatusActive {
		t.Errorf("renewal status = %q, want active", renewed.Status)
	}
	if renewed.SupersedesGrantID == nil || *renewed.SupersedesGrantID != g1.ID {
		t.Errorf("renewal must supersede g1, got %v", renewed.SupersedesGrantID)
	}
	prior, _ := store.GetJitGrantByID(ctx(), testAccountID, g1.ID)
	if prior.Status != types.GrantStatusSuperseded {
		t.Errorf("g1 status = %q, want superseded", prior.Status)
	}
	// Membership untouched (no removals; same backing group).
	if _, removes := account.addRemoveCalls(); removes != 0 {
		t.Errorf("extend must NOT remove membership, got %d", removes)
	}
	if !hasActivity(events, activity.JitAccessExtended) {
		t.Errorf("expected JitAccessExtended; got %v", activitiesOf(events))
	}

	// Over-max rejected; non-approver rejected; re-extending the superseded grant rejected.
	if _, err := m.ExtendByAdmin(ctx(), testAccountID, admin, renewed.ID, 999); err == nil {
		t.Error("expected over-max extend to be rejected")
	}
	if _, err := m.ExtendByAdmin(ctx(), testAccountID, requester, renewed.ID, 30); err == nil {
		t.Error("expected non-approver extend to be rejected")
	}
	if _, err := m.ExtendByAdmin(ctx(), testAccountID, admin, g1.ID, 30); err == nil {
		t.Error("expected re-extending a superseded grant to be rejected")
	}
}

func TestExtendByAdmin_ConcurrentExtendsOnlyOneWins(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g1, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if _, err := m.Approve(ctx(), testAccountID, admin, g1.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := m.ExtendByAdmin(ctx(), testAccountID, admin, g1.ID, 90)
			results[idx] = err
		}(i)
	}
	wg.Wait()

	wins, losses := 0, 0
	for _, err := range results {
		if err == nil {
			wins++
		} else {
			losses++
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("concurrent extend: wins=%d losses=%d, want 1/1", wins, losses)
	}

	// Invariant: at most one active grant for the (user,policy).
	activeCount := 0
	for _, g := range store.allGrants() {
		if g.Status == types.GrantStatusActive && g.RequesterUserID == requester.UserID && g.PolicyID == p.ID {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Errorf("active grants for (user,policy) = %d, want exactly 1", activeCount)
	}
}

// ---------------------------------------------------------------------------
// Scheduler hooks
// ---------------------------------------------------------------------------

func TestAutoDenyPending_DeniesPendingEmitsDenied(t *testing.T) {
	m, store, _, events := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	events.events = nil

	fresh, _ := store.GetJitGrantByID(ctx(), testAccountID, g.ID)
	out, err := m.AutoDenyPending(ctx(), fresh)
	if err != nil {
		t.Fatalf("AutoDenyPending: %v", err)
	}
	if out.Status != types.GrantStatusDenied {
		t.Errorf("status = %q, want denied", out.Status)
	}
	if !hasActivity(events, activity.JitAccessDenied) {
		t.Errorf("expected JitAccessDenied; got %v", activitiesOf(events))
	}
}

func TestRetryFailed_ReactivatesFromFailed(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	// Drive the grant to failed via an apply failure.
	account.applyErr = errors.New("boom")
	if _, err := m.Approve(ctx(), testAccountID, admin, g.ID); err == nil {
		t.Fatal("expected approve to fail")
	}
	failed, _ := store.GetJitGrantByID(ctx(), testAccountID, g.ID)
	if failed.Status != types.GrantStatusFailed {
		t.Fatalf("precondition: want failed, got %q", failed.Status)
	}

	// Recover NetBird; retry should reactivate.
	account.applyErr = nil
	account.calls = nil
	if err := m.RetryFailed(ctx(), failed); err != nil {
		t.Fatalf("RetryFailed: %v", err)
	}
	got, _ := store.GetJitGrantByID(ctx(), testAccountID, g.ID)
	if got.Status != types.GrantStatusActive {
		t.Errorf("status = %q, want active after retry", got.Status)
	}
	if adds, _ := account.addRemoveCalls(); adds != 1 {
		t.Errorf("retry should re-add the group once, got %d", adds)
	}
}

// ---------------------------------------------------------------------------
// TerminateGrantsForPolicy (the grantCanceller seam)
// ---------------------------------------------------------------------------

func TestTerminateGrantsForPolicy_VoidsAllAndRemovesMemberships(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)

	// One active grant (membership held) + one pending zombie on the same policy.
	active, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	if _, err := m.Approve(ctx(), testAccountID, admin, active.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	pending, _ := m.RequestAccess(ctx(), testAccountID, jit.Caller{UserID: "u2", Groups: []string{"eng"}}, p.ID, 60, "")
	account.calls = nil

	if err := m.TerminateGrantsForPolicy(ctx(), testAccountID, p.ID, "policy deleted"); err != nil {
		t.Fatalf("TerminateGrantsForPolicy: %v", err)
	}

	gotActive, _ := store.GetJitGrantByID(ctx(), testAccountID, active.ID)
	if gotActive.Status != types.GrantStatusRevoked {
		t.Errorf("active grant status = %q, want revoked", gotActive.Status)
	}
	gotPending, _ := store.GetJitGrantByID(ctx(), testAccountID, pending.ID)
	if gotPending.Status != types.GrantStatusCancelled {
		t.Errorf("pending grant status = %q, want cancelled", gotPending.Status)
	}
	// The active grant's membership was removed.
	if _, removes := account.addRemoveCalls(); removes != 1 {
		t.Errorf("expected one membership removal (the active grant), got %d", removes)
	}
}

// ---------------------------------------------------------------------------
// ListMine
// ---------------------------------------------------------------------------

func TestListMine_ReturnsRequesterGrantsFilteredByStatus(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	p := seedGrantPolicy(t, store)
	g1, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")
	// Cancel g1 so it is terminal; create a second pending one.
	if _, err := m.Cancel(ctx(), testAccountID, requester, g1.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	g2, _ := m.RequestAccess(ctx(), testAccountID, requester, p.ID, 60, "")

	all, err := m.ListMine(ctx(), testAccountID, requester, nil)
	if err != nil {
		t.Fatalf("ListMine all: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListMine(nil) returned %d, want 2", len(all))
	}

	pendingStatus := types.GrantStatusPending
	pendingOnly, err := m.ListMine(ctx(), testAccountID, requester, &pendingStatus)
	if err != nil {
		t.Fatalf("ListMine pending: %v", err)
	}
	if len(pendingOnly) != 1 || pendingOnly[0].ID != g2.ID {
		t.Errorf("ListMine(pending) = %v, want only %q", pendingOnly, g2.ID)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func isStatusType(err error, t status.Type) bool {
	s, ok := status.FromError(err)
	return ok && s.Type() == t
}

func hasActivity(events *fakeEvents, a activity.Activity) bool {
	for _, e := range events.events {
		if e.activity == a {
			return true
		}
	}
	return false
}

func activitiesOf(events *fakeEvents) []activity.ActivityDescriber {
	out := make([]activity.ActivityDescriber, 0, len(events.events))
	for _, e := range events.events {
		out = append(out, e.activity)
	}
	return out
}

// activeGrant inserts an already-active grant directly into the store so GATE
// tests can manufacture multiple active grants on the same backing group.
func activeGrant(t *testing.T, store *fakeStore, id, policyID, userID string) *types.JitGrant {
	t.Helper()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	g := &types.JitGrant{
		ID:                       id,
		AccountID:                testAccountID,
		PolicyID:                 policyID,
		RequesterUserID:          userID,
		RequestedDurationMinutes: 60,
		Status:                   types.GrantStatusActive,
		RequestedAt:              now,
		ActivatedAt:              &now,
		ExpiresAt:                &exp,
	}
	if err := store.CreateJitGrant(context.Background(), g); err != nil {
		t.Fatalf("seed active grant: %v", err)
	}
	return g
}
