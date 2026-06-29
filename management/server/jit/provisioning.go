package jit

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/xid"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// DefaultMarker is the prefix applied to every JIT-owned NetBird object name.
// The server-side filter (Task 10) identifies JIT-owned groups and policies by
// this prefix and hides them from general-purpose list endpoints.
const DefaultMarker = "jit:"

// provisioner is the minimal interface consumed by the provisioning helpers.
// account.Manager satisfies CreateGroup, DeleteGroup, SavePolicy, DeletePolicy.
// resources.Manager satisfies GetAllResourcesInAccount.
// Unit tests satisfy the whole interface with fakeProvisioner — no real DB needed.
type provisioner interface {
	// CreateGroup creates a new group. When newGroup.ID is empty and
	// newGroup.Issued == types.GroupIssuedAPI the store assigns a new xid and
	// writes it back to newGroup.ID, so callers read the ID after the call.
	CreateGroup(ctx context.Context, accountID, userID string, newGroup *types.Group) error

	// DeleteGroup removes the group identified by groupID.
	DeleteGroup(ctx context.Context, accountID, userID, groupID string) error

	// SavePolicy creates (create==true) or updates (create==false) a policy.
	// On create, if policy.ID is empty the manager assigns a new xid and writes
	// it back into policy.ID. The returned *types.Policy reflects the persisted state.
	SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy, create bool) (*types.Policy, error)

	// DeletePolicy removes the policy identified by policyID.
	DeletePolicy(ctx context.Context, accountID, policyID, userID string) error

	// GetAllResourcesInAccount returns all network resources for the account so
	// the provisioner can resolve each target resource's Type
	// (host/subnet/domain) for the DestinationResource field in the policy rule.
	GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*resourceTypes.NetworkResource, error)
}

// ProvisionSpec carries everything ProvisionBacking needs to create the
// backing group and access policy for a JIT policy.
type ProvisionSpec struct {
	// Name is the human-readable JIT policy name (will be marker-prefixed).
	Name string
	// Description is written to the NetBird access-policy description.
	Description string
	// TargetResourceIDs are the NetBird resource IDs this policy gates.
	TargetResourceIDs []string
	// Traffic is the allowed protocol/ports on the provisioned policy.
	Traffic types.JitTraffic
}

// MarkerName returns marker+name — the prefix that lets hidden-object filters
// identify JIT-owned NetBird groups and policies.
func MarkerName(marker, name string) string {
	return marker + name
}

// IsJitOwnedName reports whether name belongs to a JIT-owned NetBird object.
// It returns true iff name is prefixed with DefaultMarker ("jit:"). Used by
// the groups and policies list handlers (Task 10) to hide JIT backing objects
// from the standard management UI without altering their behavior.
func IsJitOwnedName(name string) bool {
	return strings.HasPrefix(name, DefaultMarker)
}

// AssertApiGroup guards the hard invariant: JIT must only ever touch
// API-issued groups. It returns a PreconditionFailed error when the group
// carries a different issuer (JWT or integration).
func AssertApiGroup(g *types.Group) error {
	if g.Issued != "" && g.Issued != types.GroupIssuedAPI {
		return status.Errorf(
			status.PreconditionFailed,
			"jit: backing group %s is %s-issued; JIT only manages api-issued groups",
			g.ID, g.Issued,
		)
	}
	return nil
}

// indexResourceTypes fetches all network resources in the account and returns
// a map of resourceID → types.ResourceType so callers can populate
// PolicyRule.DestinationResource.Type without a per-ID round-trip.
func indexResourceTypes(
	ctx context.Context,
	p provisioner,
	accountID, userID string,
) (map[string]types.ResourceType, error) {
	resources, err := p.GetAllResourcesInAccount(ctx, accountID, userID)
	if err != nil {
		return nil, fmt.Errorf("jit: fetch resources for account %s: %w", accountID, err)
	}
	idx := make(map[string]types.ResourceType, len(resources))
	for _, r := range resources {
		idx[r.ID] = types.ResourceType(r.Type)
	}
	return idx, nil
}

// buildPolicy constructs the types.Policy for a JIT access rule: one
// PolicyRule per target resource, each with:
//
//   - Sources: []string{backingGroupID}
//   - DestinationResource: types.Resource{ID: resourceID, Type: resourceType}
//   - Action: accept, Bidirectional: false
//   - Protocol and Ports from spec.Traffic
//
// Policy.ID and Policy.AccountID are left empty on create so that SavePolicy
// (with create=true) assigns them via validatePolicy.
func buildPolicy(
	marker string,
	backingGroupID string,
	spec ProvisionSpec,
	rTypeIdx map[string]types.ResourceType,
) *types.Policy {
	rules := make([]*types.PolicyRule, 0, len(spec.TargetResourceIDs))
	for i, rid := range spec.TargetResourceIDs {
		rules = append(rules, &types.PolicyRule{
			// Each rule gets a unique xid so validatePolicy's fallback
			// (ruleCopy.ID = policy.ID) never fires — which would make
			// all N rules share the same primary key and cause a store
			// unique-constraint violation.
			ID:          xid.New().String(),
			Name:        MarkerName(marker, fmt.Sprintf("%s-%d", spec.Name, i)),
			Description: "Managed by JIT — do not edit",
			Enabled:     true,
			Action:      types.PolicyTrafficActionAccept,
			Sources:     []string{backingGroupID},
			DestinationResource: types.Resource{
				ID:   rid,
				Type: rTypeIdx[rid],
			},
			Bidirectional: false,
			Protocol:      types.PolicyRuleProtocolType(spec.Traffic.Protocol),
			Ports:         spec.Traffic.Ports,
		})
	}

	return &types.Policy{
		// ID and AccountID assigned by SavePolicy when empty.
		Name:        MarkerName(marker, spec.Name),
		Description: "Managed by JIT — do not edit",
		Enabled:     true,
		Rules:       rules,
	}
}

// ProvisionBacking creates the marker-tagged API group and access policy for
// a JIT policy.
//
//  1. Creates the backing group (Issued: API, name = MarkerName(DefaultMarker, spec.Name)).
//  2. Indexes all account resources to resolve destination resource types.
//  3. Creates the NetBird access policy (one rule per target resource).
//  4. If policy creation fails, best-effort deletes the backing group (rollback)
//     before returning the error.
//
// Returns the backing group ID and the NetBird policy ID on success.
func ProvisionBacking(
	ctx context.Context,
	p provisioner,
	accountID, userID string,
	spec ProvisionSpec,
) (backingGroupID, netbirdPolicyID string, err error) {
	// Step 1: create the backing group.
	// Leave ID empty — CreateGroup→validateNewGroup assigns a new xid.
	group := &types.Group{
		Name:   MarkerName(DefaultMarker, spec.Name),
		Issued: types.GroupIssuedAPI,
	}
	if err := p.CreateGroup(ctx, accountID, userID, group); err != nil {
		return "", "", fmt.Errorf("jit: create backing group: %w", err)
	}
	backingGroupID = group.ID

	// Step 2: resolve resource types.
	rTypeIdx, err := indexResourceTypes(ctx, p, accountID, userID)
	if err != nil {
		_ = p.DeleteGroup(ctx, accountID, userID, backingGroupID) // best-effort rollback
		return "", "", err
	}

	// Step 3: create the access policy; roll back the group on failure.
	policy := buildPolicy(DefaultMarker, backingGroupID, spec, rTypeIdx)
	saved, err := p.SavePolicy(ctx, accountID, userID, policy, true)
	if err != nil {
		_ = p.DeleteGroup(ctx, accountID, userID, backingGroupID) // best-effort rollback
		return "", "", fmt.Errorf("jit: create access policy: %w", err)
	}

	return backingGroupID, saved.ID, nil
}

// UpdateBackingPolicy re-syncs the NetBird access policy when a JIT policy's
// name, resources, or traffic settings change. The backing group is not
// renamed — only the policy rules are replaced.
//
// No-op if jitPolicy.BackingGroupID or jitPolicy.NetbirdPolicyID is empty
// (policy not yet provisioned).
func UpdateBackingPolicy(
	ctx context.Context,
	p provisioner,
	accountID, userID string,
	jitPolicy *types.JitPolicy,
	spec ProvisionSpec,
) error {
	if jitPolicy.BackingGroupID == "" || jitPolicy.NetbirdPolicyID == "" {
		return nil
	}

	rTypeIdx, err := indexResourceTypes(ctx, p, accountID, userID)
	if err != nil {
		return err
	}

	policy := buildPolicy(DefaultMarker, jitPolicy.BackingGroupID, spec, rTypeIdx)
	// Preserve the existing IDs so SavePolicy performs an update, not a create.
	policy.ID = jitPolicy.NetbirdPolicyID
	policy.AccountID = accountID

	if _, err := p.SavePolicy(ctx, accountID, userID, policy, false); err != nil {
		return fmt.Errorf("jit: update access policy %s: %w", jitPolicy.NetbirdPolicyID, err)
	}
	return nil
}

// DeprovisionBacking deletes the NetBird access policy and then the backing
// group. Both deletions are idempotent: a not-found error is swallowed so the
// function is safe to retry.
//
// Order: policy first (removes the ACL), then group (removes the membership
// handle). This mirrors the TypeScript sidecar's deprovisionBacking.
func DeprovisionBacking(
	ctx context.Context,
	p provisioner,
	accountID, userID string,
	backingGroupID, netbirdPolicyID string,
) error {
	if netbirdPolicyID != "" {
		if err := p.DeletePolicy(ctx, accountID, netbirdPolicyID, userID); err != nil && !isNotFound(err) {
			return fmt.Errorf("jit: delete access policy %s: %w", netbirdPolicyID, err)
		}
	}

	if backingGroupID != "" {
		if err := p.DeleteGroup(ctx, accountID, userID, backingGroupID); err != nil && !isNotFound(err) {
			return fmt.Errorf("jit: delete backing group %s: %w", backingGroupID, err)
		}
	}

	return nil
}

// isNotFound reports whether err is a status.Error with type NotFound.
func isNotFound(err error) bool {
	s, ok := status.FromError(err)
	return ok && s.Type() == status.NotFound
}
