package jit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
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

	// GetPolicy returns an existing NetBird access-control policy by ID. JIT
	// reads the source policy that a mirror-type JIT policy is based on through
	// this (account.Manager satisfies it). userID is the caller, so the manager
	// runs its own permission check — mirror create/update is admin-gated.
	GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error)
}

// ProvisionSpec carries everything ProvisionBacking needs to create the
// backing group and access policy for a JIT policy.
type ProvisionSpec struct {
	// Name is the human-readable JIT policy name (will be marker-prefixed).
	Name string
	// Description is written to the NetBird access-policy description.
	Description string
	// TargetResourceIDs are the NetBird resource IDs this policy gates.
	// Used only for resource-based (custom) policies; ignored when SourcePolicy
	// is set.
	TargetResourceIDs []string
	// Traffic is the allowed protocol/ports on the provisioned policy.
	// Used only for resource-based (custom) policies; ignored when SourcePolicy
	// is set.
	Traffic types.JitTraffic
	// SourcePolicy, when non-nil, makes this a mirror-type policy: the access
	// policy is built by copying this existing policy's enabled rules (swapping
	// the source to the backing group) rather than from TargetResourceIDs. The
	// caller resolves and validates it (admin-gated) before provisioning.
	SourcePolicy *types.Policy
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

// buildPolicyFromSource constructs the JIT access policy for a mirror-type JIT
// policy by copying spec.SourcePolicy's rules. For each *enabled* source rule
// — accept and drop alike, so the mirror can never grant more than the source —
// it emits a rule that is identical except:
//
//   - Sources is replaced with []string{backingGroupID} and SourceResource is
//     cleared: JIT is always group-sourced from its own backing group; the
//     source rule's own sources are discarded (who-can-request is the JIT
//     policy's eligibility, not the source policy's source groups).
//   - Bidirectional is forced false (JIT grants are one-way inbound, matching
//     the resource-based path).
//   - The rule gets a fresh xid and a marker-prefixed name so it is hidden.
//
// The destination side (Destinations, DestinationResource), Action, Protocol,
// Ports and PortRanges are copied verbatim, and the source policy's
// SourcePostureChecks are carried onto the mirror. Returns an error if the
// source has no enabled rule to mirror (a JIT policy that grants nothing is
// never useful and would silently no-op).
func buildPolicyFromSource(marker, backingGroupID string, spec ProvisionSpec) (*types.Policy, error) {
	src := spec.SourcePolicy
	rules := make([]*types.PolicyRule, 0, len(src.Rules))
	for _, r := range src.Rules {
		if !r.Enabled {
			continue
		}
		rules = append(rules, &types.PolicyRule{
			ID:                  xid.New().String(),
			Name:                MarkerName(marker, fmt.Sprintf("%s-%d", spec.Name, len(rules))),
			Description:         "Managed by JIT — do not edit",
			Enabled:             true,
			Action:              r.Action,
			Sources:             []string{backingGroupID},
			SourceResource:      types.Resource{},
			Destinations:        append([]string(nil), r.Destinations...),
			DestinationResource: r.DestinationResource,
			Bidirectional:       false,
			Protocol:            r.Protocol,
			Ports:               append([]string(nil), r.Ports...),
			PortRanges:          append([]types.RulePortRange(nil), r.PortRanges...),
		})
	}
	if len(rules) == 0 {
		return nil, status.Errorf(
			status.PreconditionFailed,
			"jit: source policy %q has no enabled rule to mirror", src.Name,
		)
	}

	return &types.Policy{
		// ID and AccountID assigned by SavePolicy when empty.
		Name:                MarkerName(marker, spec.Name),
		Description:         "Managed by JIT — do not edit",
		Enabled:             true,
		Rules:               rules,
		SourcePostureChecks: append([]string(nil), src.SourcePostureChecks...),
	}, nil
}

// FingerprintSource returns a stable hash of the mirror-relevant content of a
// source policy: for each enabled rule, its action / protocol / ports /
// port-ranges / destinations / destination-resource, plus the policy's posture
// checks. It deliberately ignores the source side (Sources/SourceResource),
// rule order, rule and policy names, and the Enabled flag — the things JIT
// discards or controls itself — so only a change that would alter what a mirror
// grants flags drift ("source changed — re-sync"). A mirror-type JIT policy
// stores this at sync time; admin reads compare it against the live source.
func FingerprintSource(p *types.Policy) string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, len(p.Rules))
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}
		ports := append([]string(nil), r.Ports...)
		sort.Strings(ports)
		dests := append([]string(nil), r.Destinations...)
		sort.Strings(dests)
		ranges := make([]string, 0, len(r.PortRanges))
		for _, pr := range r.PortRanges {
			ranges = append(ranges, fmt.Sprintf("%d-%d", pr.Start, pr.End))
		}
		sort.Strings(ranges)
		parts = append(parts, fmt.Sprintf(
			"a=%s;proto=%s;ports=%s;ranges=%s;dst=%s;dres=%s/%s",
			r.Action, r.Protocol,
			strings.Join(ports, ","), strings.Join(ranges, ","),
			strings.Join(dests, ","),
			r.DestinationResource.ID, r.DestinationResource.Type,
		))
	}
	sort.Strings(parts)
	checks := append([]string(nil), p.SourcePostureChecks...)
	sort.Strings(checks)

	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte("|"))
	}
	_, _ = h.Write([]byte("posture=" + strings.Join(checks, ",")))
	return hex.EncodeToString(h.Sum(nil))
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

	// Step 2: build the access policy (mirror a source policy, or one rule per
	// target resource); roll back the group on failure.
	policy, err := buildBackingPolicy(ctx, p, accountID, userID, backingGroupID, spec)
	if err != nil {
		_ = p.DeleteGroup(ctx, accountID, userID, backingGroupID) // best-effort rollback
		return "", "", err
	}

	// Step 3: create the access policy; roll back the group on failure.
	saved, err := p.SavePolicy(ctx, accountID, userID, policy, true)
	if err != nil {
		_ = p.DeleteGroup(ctx, accountID, userID, backingGroupID) // best-effort rollback
		return "", "", fmt.Errorf("jit: create access policy: %w", err)
	}

	return backingGroupID, saved.ID, nil
}

// buildBackingPolicy builds the NetBird access policy for a JIT policy: it
// mirrors spec.SourcePolicy when the spec is policy-based, otherwise it builds
// one rule per target resource (resolving each resource's type). Shared by
// ProvisionBacking (create) and UpdateBackingPolicy (re-sync).
func buildBackingPolicy(
	ctx context.Context,
	p provisioner,
	accountID, userID, backingGroupID string,
	spec ProvisionSpec,
) (*types.Policy, error) {
	if spec.SourcePolicy != nil {
		return buildPolicyFromSource(DefaultMarker, backingGroupID, spec)
	}
	rTypeIdx, err := indexResourceTypes(ctx, p, accountID, userID)
	if err != nil {
		return nil, err
	}
	return buildPolicy(DefaultMarker, backingGroupID, spec, rTypeIdx), nil
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

	policy, err := buildBackingPolicy(ctx, p, accountID, userID, jitPolicy.BackingGroupID, spec)
	if err != nil {
		return err
	}
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
