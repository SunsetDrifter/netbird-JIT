package jit

import (
	"context"
	"fmt"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// defaultTraffic is applied when a create request omits the traffic field:
// allow all protocols/ports (mirrors the sidecar's DEFAULT_TRAFFIC).
var defaultTraffic = types.JitTraffic{Protocol: "all"}

// CreateJitPolicyInput is the validated payload for CreatePolicy. It mirrors the
// sidecar's CreateJitPolicyRequest. Traffic and PendingTTLMinutes are pointers
// so an omitted value can be distinguished from a zero value and defaulted.
type CreateJitPolicyInput struct {
	Name        string
	Description string
	// TargetResourceIDs (resource-based) and SourcePolicyID (mirror-type) are
	// mutually exclusive — provide exactly one.
	TargetResourceIDs  []string
	SourcePolicyID     string
	Traffic            *types.JitTraffic
	MaxDurationMinutes int
	RequestableBy      types.JitRequestableBy
	ApproverCriteria   types.JitApproverCriteria
	PendingTTLMinutes  *int
}

// UpdateJitPolicyInput is a sparse patch for UpdatePolicy. Every field is a
// pointer: nil means "leave unchanged" (mirrors the sidecar's partial
// UpdateJitPolicyRequest). Changing Name, TargetResourceIDs, or Traffic
// re-syncs the backing NetBird access policy.
type UpdateJitPolicyInput struct {
	Name               *string
	Description        *string
	TargetResourceIDs  *[]string
	SourcePolicyID     *string
	Traffic            *types.JitTraffic
	MaxDurationMinutes *int
	RequestableBy      *types.JitRequestableBy
	ApproverCriteria   *types.JitApproverCriteria
	PendingTTLMinutes  *int
	Enabled            *bool
}

// CreatePolicy persists a JIT policy, provisions its backing group + access
// policy, and writes the provisioned IDs back onto the row.
//
// Order mirrors the sidecar (policyService.ts):
//  1. Persist the row first (Enabled=true, backing IDs empty) so it has a stable id.
//  2. Provision the backing group + NetBird policy.
//  3. Write the backing IDs back onto the row.
//  4. Emit JitPolicyCreated.
//
// If provisioning (or the write-back) fails, the persisted row is deleted
// (rollback) and the error is returned — no event is emitted.
func (m *Manager) CreatePolicy(
	ctx context.Context,
	accountID, userID string,
	in CreateJitPolicyInput,
) (*types.JitPolicy, error) {
	// A JIT policy is either policy-based (mirrors an existing access policy) or
	// resource-based (a hand-picked resource list) — provide exactly one.
	hasSource := in.SourcePolicyID != ""
	hasResources := len(in.TargetResourceIDs) > 0
	if hasSource == hasResources {
		return nil, status.Errorf(status.InvalidArgument,
			"jit: provide exactly one of sourcePolicyId or targetResourceIds")
	}
	// A mirror-type copies the source policy's traffic verbatim, so an explicit
	// traffic field would be silently ignored — reject it (UpdatePolicy does the
	// same).
	if hasSource && in.Traffic != nil {
		return nil, status.Errorf(status.InvalidArgument,
			"jit: traffic cannot be set on a policy-based JIT policy")
	}

	// For a mirror-type, resolve + validate the source up front so a bad id
	// fails before we persist or provision anything.
	var source *types.Policy
	if hasSource {
		s, err := m.resolveSourcePolicy(ctx, accountID, userID, in.SourcePolicyID)
		if err != nil {
			return nil, err
		}
		source = s
	}

	traffic := defaultTraffic
	if in.Traffic != nil {
		traffic = *in.Traffic
	}
	pendingTTL := m.defaultPendingTTL
	if in.PendingTTLMinutes != nil {
		pendingTTL = *in.PendingTTLMinutes
	}

	// Step 1: persist first (no backing ids yet) so we have a stable id.
	policy := &types.JitPolicy{
		ID:                 xid.New().String(),
		AccountID:          accountID,
		Name:               in.Name,
		Description:        in.Description,
		TargetResourceIDs:  in.TargetResourceIDs,
		Traffic:            traffic,
		MaxDurationMinutes: in.MaxDurationMinutes,
		RequestableBy:      in.RequestableBy,
		ApproverCriteria:   in.ApproverCriteria,
		PendingTTLMinutes:  pendingTTL,
		Enabled:            true,
		CreatedByUserID:    userID,
	}
	// Snapshot the source's name + fingerprint for mirror-type policies so the
	// user-facing endpoints and the drift check have them without re-reading the
	// source under the caller's permissions.
	if source != nil {
		policy.SourcePolicyID = in.SourcePolicyID
		policy.SourcePolicyName = source.Name
		policy.SourceFingerprint = FingerprintSource(source)
	}
	if err := m.store.SaveJitPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("jit: persist policy: %w", err)
	}

	// Step 2: provision the backing group + NetBird policy; roll back on failure.
	// ProvisionBacking rolls back its own partial state before returning an
	// error, so the only cleanup needed here is deleting the persisted row.
	backingGroupID, netbirdPolicyID, err := ProvisionBacking(ctx, m.prov, accountID, userID, ProvisionSpec{
		Name:              policy.Name,
		Description:       policy.Description,
		TargetResourceIDs: policy.TargetResourceIDs,
		Traffic:           policy.Traffic,
		SourcePolicy:      source,
	})
	if err != nil {
		m.rollbackCreateRow(ctx, accountID, policy.ID, err)
		return nil, err
	}

	// Step 3: write the backing IDs back onto the row. On failure the backing
	// objects are already live, so we must deprovision them as well as delete
	// the row — otherwise they are permanently orphaned with no row to find
	// their IDs.
	policy.BackingGroupID = backingGroupID
	policy.NetbirdPolicyID = netbirdPolicyID
	if err := m.store.SaveJitPolicy(ctx, policy); err != nil {
		writeBackErr := fmt.Errorf("jit: write back backing ids: %w", err)
		m.rollbackCreateWithBacking(ctx, accountID, userID, policy.ID, backingGroupID, netbirdPolicyID, writeBackErr)
		return nil, writeBackErr
	}

	// Step 4: audit.
	m.events.StoreEvent(ctx, userID, policy.ID, accountID, activity.JitPolicyCreated, map[string]any{
		"name":            policy.Name,
		"backingGroupId":  backingGroupID,
		"netbirdPolicyId": netbirdPolicyID,
	})
	return policy, nil
}

// rollbackCreateRow deletes a persisted-but-unprovision policy row after a
// step-2 (ProvisionBacking) failure. ProvisionBacking already rolled back its
// own partial state before returning, so only the row needs cleaning up.
func (m *Manager) rollbackCreateRow(ctx context.Context, accountID, policyID string, cause error) {
	if delErr := m.store.DeleteJitPolicy(ctx, accountID, policyID); delErr != nil {
		log.WithContext(ctx).Errorf("jit: failed to roll back policy row %s after provisioning error (%v): %v", policyID, cause, delErr)
	} else {
		log.WithContext(ctx).Warnf("jit: policy %s provisioning failed; rolled back row: %v", policyID, cause)
	}
}

// rollbackCreateWithBacking is called when the step-3 write-back fails: the
// backing group and NetBird policy are already live, so we must deprovision
// them before deleting the row. Both cleanup steps are best-effort — errors are
// logged but do not mask the original write-back error returned to the caller.
func (m *Manager) rollbackCreateWithBacking(ctx context.Context, accountID, userID, policyID, backingGroupID, netbirdPolicyID string, cause error) {
	if deprovErr := DeprovisionBacking(ctx, m.prov, accountID, userID, backingGroupID, netbirdPolicyID); deprovErr != nil {
		log.WithContext(ctx).Errorf("jit: failed to deprovision backing objects for policy %s after write-back error (%v): %v", policyID, cause, deprovErr)
	}
	if delErr := m.store.DeleteJitPolicy(ctx, accountID, policyID); delErr != nil {
		log.WithContext(ctx).Errorf("jit: failed to roll back policy row %s after write-back error (%v): %v", policyID, cause, delErr)
	} else {
		log.WithContext(ctx).Warnf("jit: policy %s write-back failed; rolled back row and backing objects: %v", policyID, cause)
	}
}

// UpdatePolicy applies a sparse patch to a JIT policy and re-syncs the backing
// NetBird access policy when the patch changes the policy's name, target
// resources, or traffic. Account-scoped: a policy in another account is not
// found.
func (m *Manager) UpdatePolicy(
	ctx context.Context,
	accountID, userID, policyID string,
	patch UpdateJitPolicyInput,
) (*types.JitPolicy, error) {
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, policyID)
	if err != nil {
		return nil, err
	}

	wasMirror := policy.SourcePolicyID != ""

	// A JIT policy's flavor is fixed at creation. A mirror-type can be re-pointed
	// (a new sourcePolicyId) or re-synced (the same one), but neither flavor can
	// be converted to the other in place — delete and recreate for that.
	switch {
	case wasMirror && (patch.TargetResourceIDs != nil || patch.Traffic != nil):
		return nil, status.Errorf(status.InvalidArgument,
			"jit: cannot set targetResourceIds/traffic on a policy-based JIT policy; delete and recreate to change type")
	case !wasMirror && patch.SourcePolicyID != nil:
		return nil, status.Errorf(status.InvalidArgument,
			"jit: cannot set sourcePolicyId on a resource-based JIT policy; delete and recreate to change type")
	case patch.SourcePolicyID != nil && *patch.SourcePolicyID == "":
		return nil, status.Errorf(status.InvalidArgument, "jit: sourcePolicyId cannot be cleared")
	}

	// patch.SourcePolicyID != nil ⇒ an explicit re-point/re-sync: resolve the
	// (new or same) source up front so a bad id fails before we mutate anything.
	resync := patch.SourcePolicyID != nil
	var source *types.Policy
	if resync {
		s, err := m.resolveSourcePolicy(ctx, accountID, userID, *patch.SourcePolicyID)
		if err != nil {
			return nil, err
		}
		source = s
	}

	oldName := policy.Name
	applyPatch(policy, patch)

	// Persist the patch first WITHOUT advancing the source snapshot. If the
	// backing-policy rebuild below fails, the stored SourceFingerprint still
	// reflects the last successful sync, so drift stays detectable instead of
	// being hidden by a fingerprint that ran ahead of the actual backing policy.
	if err := m.store.SaveJitPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("jit: persist policy update: %w", err)
	}

	// Decide whether to rebuild the backing NetBird policy, and from what.
	//
	// Mirror-type: rebuild only on an explicit re-sync/re-point. A JIT-policy
	// rename alone does not rebuild it — the backing policy's name suffix is
	// cosmetic (it stays hidden by the "jit:" prefix), and re-mirroring on a
	// rename would silently pull in source drift.
	//
	// Resource-type: rebuild when resources, traffic, or the name change (the
	// name flows into the per-resource rule names), exactly as before.
	var (
		spec                 ProvisionSpec
		touchesBackingPolicy bool
	)
	if policy.SourcePolicyID != "" {
		touchesBackingPolicy = resync
		spec = ProvisionSpec{Name: policy.Name, Description: policy.Description, SourcePolicy: source}
	} else {
		touchesBackingPolicy = patch.TargetResourceIDs != nil ||
			patch.Traffic != nil ||
			(patch.Name != nil && *patch.Name != oldName)
		spec = ProvisionSpec{
			Name:              policy.Name,
			Description:       policy.Description,
			TargetResourceIDs: policy.TargetResourceIDs,
			Traffic:           policy.Traffic,
		}
	}

	if touchesBackingPolicy {
		// UpdateBackingPolicy replaces the access policy, so its ID changes —
		// capture the new one to persist below.
		newPolicyID, err := UpdateBackingPolicy(ctx, m.prov, accountID, userID, policy, spec)
		if err != nil {
			return nil, err
		}
		policy.NetbirdPolicyID = newPolicyID
	}

	// The backing policy is now rebuilt from the (re)pointed source. Persist the
	// new backing-policy id and, on a re-sync, the refreshed source snapshot.
	// Doing this only AFTER a successful rebuild keeps drift detectable when the
	// rebuild fails: the stored fingerprint still reflects the last good sync.
	if touchesBackingPolicy {
		if resync {
			policy.SourcePolicyName = source.Name
			policy.SourceFingerprint = FingerprintSource(source)
		}
		if err := m.store.SaveJitPolicy(ctx, policy); err != nil {
			return nil, fmt.Errorf("jit: persist backing policy id / source snapshot: %w", err)
		}
	}

	m.events.StoreEvent(ctx, userID, policy.ID, accountID, activity.JitPolicyUpdated, map[string]any{
		"name":   policy.Name,
		"fields": changedFields(patch),
	})
	return policy, nil
}

// applyPatch mutates policy in place with the non-nil fields of patch. The
// caller owns the *types.JitPolicy (a fresh copy from the store), so this does
// not mutate shared state.
func applyPatch(policy *types.JitPolicy, patch UpdateJitPolicyInput) {
	if patch.Name != nil {
		policy.Name = *patch.Name
	}
	if patch.Description != nil {
		policy.Description = *patch.Description
	}
	if patch.TargetResourceIDs != nil {
		policy.TargetResourceIDs = *patch.TargetResourceIDs
	}
	if patch.SourcePolicyID != nil {
		policy.SourcePolicyID = *patch.SourcePolicyID
	}
	if patch.Traffic != nil {
		policy.Traffic = *patch.Traffic
	}
	if patch.MaxDurationMinutes != nil {
		policy.MaxDurationMinutes = *patch.MaxDurationMinutes
	}
	if patch.RequestableBy != nil {
		policy.RequestableBy = *patch.RequestableBy
	}
	if patch.ApproverCriteria != nil {
		policy.ApproverCriteria = *patch.ApproverCriteria
	}
	if patch.PendingTTLMinutes != nil {
		policy.PendingTTLMinutes = *patch.PendingTTLMinutes
	}
	if patch.Enabled != nil {
		policy.Enabled = *patch.Enabled
	}
}

// changedFields lists the patch fields that were set, for the audit meta.
func changedFields(patch UpdateJitPolicyInput) []string {
	var fields []string
	if patch.Name != nil {
		fields = append(fields, "name")
	}
	if patch.Description != nil {
		fields = append(fields, "description")
	}
	if patch.TargetResourceIDs != nil {
		fields = append(fields, "targetResourceIds")
	}
	if patch.SourcePolicyID != nil {
		fields = append(fields, "sourcePolicyId")
	}
	if patch.Traffic != nil {
		fields = append(fields, "traffic")
	}
	if patch.MaxDurationMinutes != nil {
		fields = append(fields, "maxDurationMinutes")
	}
	if patch.RequestableBy != nil {
		fields = append(fields, "requestableBy")
	}
	if patch.ApproverCriteria != nil {
		fields = append(fields, "approverCriteria")
	}
	if patch.PendingTTLMinutes != nil {
		fields = append(fields, "pendingTtlMinutes")
	}
	if patch.Enabled != nil {
		fields = append(fields, "enabled")
	}
	return fields
}

// DeletePolicy tears down a JIT policy in a strict cascade so no grant is ever
// left pointing at a deleted policy and no backing object is orphaned:
//
//  1. Terminate every grant for the policy (voids grants + removes memberships).
//  2. Deprovision the backing objects (delete the access policy, then the group).
//  3. Delete the policy row.
//  4. Emit JitPolicyDeleted.
//
// The order is load-bearing and fail-closed: if grant termination fails the
// function returns immediately, leaving the policy and its backing objects
// intact so the caller can retry. Account-scoped.
func (m *Manager) DeletePolicy(ctx context.Context, accountID, userID, policyID string) error {
	policy, err := m.store.GetJitPolicyByID(ctx, accountID, policyID)
	if err != nil {
		return err
	}

	// Step 1: cascade — void every grant before tearing down backing objects.
	if err := m.grants.TerminateGrantsForPolicy(ctx, accountID, policyID, "policy deleted"); err != nil {
		return fmt.Errorf("jit: terminate grants for policy %s: %w", policyID, err)
	}

	// Step 2: deprovision the NetBird access policy + backing group.
	if err := DeprovisionBacking(ctx, m.prov, accountID, userID, policy.BackingGroupID, policy.NetbirdPolicyID); err != nil {
		return err
	}

	// Step 3: delete the row.
	if err := m.store.DeleteJitPolicy(ctx, accountID, policyID); err != nil {
		return fmt.Errorf("jit: delete policy row %s: %w", policyID, err)
	}

	// Step 4: audit.
	m.events.StoreEvent(ctx, userID, policyID, accountID, activity.JitPolicyDeleted, map[string]any{
		"name": policy.Name,
	})
	return nil
}

// GetPolicy returns a single account-scoped JIT policy.
func (m *Manager) GetPolicy(ctx context.Context, accountID, policyID string) (*types.JitPolicy, error) {
	return m.store.GetJitPolicyByID(ctx, accountID, policyID)
}

// ListPolicies returns all JIT policies for an account.
func (m *Manager) ListPolicies(ctx context.Context, accountID string) ([]*types.JitPolicy, error) {
	return m.store.ListJitPolicies(ctx, accountID)
}

// resolveSourcePolicy fetches and validates the access-control policy a
// mirror-type JIT policy is (re)based on. It rejects a JIT-owned policy — a JIT
// policy must not be based on another's hidden backing policy. The not-found /
// permission error from the account manager is surfaced as-is (the caller is
// admin-gated upstream).
func (m *Manager) resolveSourcePolicy(ctx context.Context, accountID, userID, sourcePolicyID string) (*types.Policy, error) {
	src, err := m.prov.GetPolicy(ctx, accountID, sourcePolicyID, userID)
	if err != nil {
		return nil, err
	}
	if IsJitOwnedName(src.Name) {
		return nil, status.Errorf(status.InvalidArgument,
			"jit: policy %q is JIT-owned and cannot be used as a source", src.Name)
	}
	return src, nil
}

// SourceDriftStatus reports, for a mirror-type JIT policy, whether its source
// access-control policy has been deleted, or has changed since the last sync
// (so the dashboard can prompt a re-sync). Both false for resource-based
// policies. userID is the (admin) caller. On a non-not-found read error it
// reports no drift, to avoid false "source changed" alarms on a transient blip.
func (m *Manager) SourceDriftStatus(ctx context.Context, accountID, userID string, p *types.JitPolicy) (drifted, deleted bool) {
	if p.SourcePolicyID == "" {
		return false, false
	}
	src, err := m.prov.GetPolicy(ctx, accountID, p.SourcePolicyID, userID)
	if err != nil {
		if isNotFound(err) {
			return false, true
		}
		log.WithContext(ctx).Warnf("jit: drift check for policy %s could not read source %s: %v", p.ID, p.SourcePolicyID, err)
		return false, false
	}
	return FingerprintSource(src) != p.SourceFingerprint, false
}
