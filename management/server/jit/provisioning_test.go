package jit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"

	"github.com/netbirdio/netbird/management/server/jit"
)

// ---------------------------------------------------------------------------
// Fake provisioner
// ---------------------------------------------------------------------------

// fakeProvisioner is an in-memory implementation of jit.provisioner for tests.
// It tracks the groups and policies it has created, and allows tests to
// inject errors at specific call sites.
type fakeProvisioner struct {
	groups    map[string]*types.Group  // groupID → group
	policies  map[string]*types.Policy // policyID → policy
	resources []*resourceTypes.NetworkResource

	// Error injection: set to a non-nil value to make the next call of that
	// method fail.
	createGroupErr  error
	savePolicyErr   error
	deleteGroupErr  error
	deletePolicyErr error
	getResourcesErr error

	// Call counters for assertions.
	createGroupCalls  int
	deleteGroupCalls  int
	savePolicyCalls   int
	deletePolicyCalls int

	// Ordering hooks (used by policy-service delete-cascade tests). Fire inside
	// DeleteGroup / DeletePolicy before the error check so callers can record
	// the interleaving of deprovisioning relative to other dependencies.
	onDeleteGroup  func()
	onDeletePolicy func()

	// Track the IDs passed to Delete* for idempotency tests.
	deletedGroups   []string
	deletedPolicies []string
}

func newFakeProvisioner(resources ...*resourceTypes.NetworkResource) *fakeProvisioner {
	return &fakeProvisioner{
		groups:    make(map[string]*types.Group),
		policies:  make(map[string]*types.Policy),
		resources: resources,
	}
}

func (f *fakeProvisioner) CreateGroup(_ context.Context, accountID, _ string, g *types.Group) error {
	f.createGroupCalls++
	if f.createGroupErr != nil {
		return f.createGroupErr
	}
	// Mimic account.Manager: assign an ID when the group is API-issued and has
	// no ID set.
	if g.ID == "" && g.Issued == types.GroupIssuedAPI {
		g.ID = fmt.Sprintf("grp-%d", f.createGroupCalls)
	}
	g.AccountID = accountID
	clone := *g
	f.groups[g.ID] = &clone
	return nil
}

func (f *fakeProvisioner) DeleteGroup(_ context.Context, _, _, groupID string) error {
	f.deleteGroupCalls++
	if f.onDeleteGroup != nil {
		f.onDeleteGroup()
	}
	if f.deleteGroupErr != nil {
		return f.deleteGroupErr
	}
	if _, ok := f.groups[groupID]; !ok {
		return status.Errorf(status.NotFound, "group %s not found", groupID)
	}
	delete(f.groups, groupID)
	f.deletedGroups = append(f.deletedGroups, groupID)
	return nil
}

func (f *fakeProvisioner) SavePolicy(_ context.Context, accountID, _ string, p *types.Policy, create bool) (*types.Policy, error) {
	f.savePolicyCalls++
	if f.savePolicyErr != nil {
		return nil, f.savePolicyErr
	}
	if create {
		// Mimic validatePolicy: assign ID when empty.
		if p.ID == "" {
			p.ID = fmt.Sprintf("pol-%d", f.savePolicyCalls)
			p.AccountID = accountID
		}
	}
	clone := *p
	f.policies[p.ID] = &clone
	return &clone, nil
}

func (f *fakeProvisioner) DeletePolicy(_ context.Context, _, policyID, _ string) error {
	f.deletePolicyCalls++
	if f.onDeletePolicy != nil {
		f.onDeletePolicy()
	}
	if f.deletePolicyErr != nil {
		return f.deletePolicyErr
	}
	if _, ok := f.policies[policyID]; !ok {
		return status.Errorf(status.NotFound, "policy %s not found", policyID)
	}
	delete(f.policies, policyID)
	f.deletedPolicies = append(f.deletedPolicies, policyID)
	return nil
}

func (f *fakeProvisioner) GetAllResourcesInAccount(_ context.Context, _, _ string) ([]*resourceTypes.NetworkResource, error) {
	if f.getResourcesErr != nil {
		return nil, f.getResourcesErr
	}
	return f.resources, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hostResource(id string) *resourceTypes.NetworkResource {
	return &resourceTypes.NetworkResource{ID: id, Type: resourceTypes.Host}
}

func domainResource(id string) *resourceTypes.NetworkResource {
	return &resourceTypes.NetworkResource{ID: id, Type: resourceTypes.Domain}
}

func basicSpec(name string, resourceIDs ...string) jit.ProvisionSpec {
	return jit.ProvisionSpec{
		Name:              name,
		Description:       "test policy",
		TargetResourceIDs: resourceIDs,
		Traffic:           types.JitTraffic{Protocol: "tcp", Ports: []string{"443"}},
	}
}

// ---------------------------------------------------------------------------
// markerName
// ---------------------------------------------------------------------------

func TestMarkerName(t *testing.T) {
	got := jit.MarkerName("jit:", "my-policy")
	want := "jit:my-policy"
	if got != want {
		t.Errorf("MarkerName = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// provisionBacking: happy path
// ---------------------------------------------------------------------------

func TestProvisionBacking_CreatesGroupAndPolicy(t *testing.T) {
	p := newFakeProvisioner(hostResource("res-1"), hostResource("res-2"))
	spec := basicSpec("my-policy", "res-1", "res-2")

	groupID, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if groupID == "" {
		t.Error("backing group ID must not be empty")
	}
	if policyID == "" {
		t.Error("netbird policy ID must not be empty")
	}

	// Verify group was actually stored.
	g, ok := p.groups[groupID]
	if !ok {
		t.Fatalf("group %s not found in fake store", groupID)
	}
	if g.Issued != types.GroupIssuedAPI {
		t.Errorf("group issued = %q, want %q", g.Issued, types.GroupIssuedAPI)
	}
	wantGroupName := jit.DefaultMarker + "my-policy"
	if g.Name != wantGroupName {
		t.Errorf("group name = %q, want %q", g.Name, wantGroupName)
	}

	// Verify policy was stored.
	pol, ok := p.policies[policyID]
	if !ok {
		t.Fatalf("policy %s not found in fake store", policyID)
	}
	wantPolicyName := jit.DefaultMarker + "my-policy"
	if pol.Name != wantPolicyName {
		t.Errorf("policy name = %q, want %q", pol.Name, wantPolicyName)
	}
	if !pol.Enabled {
		t.Error("policy must be enabled")
	}
}

func TestProvisionBacking_OneRulePerResource(t *testing.T) {
	p := newFakeProvisioner(hostResource("res-1"), domainResource("res-2"))
	spec := basicSpec("pol", "res-1", "res-2")

	groupID, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pol := p.policies[policyID]
	if len(pol.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(pol.Rules))
	}

	for i, rule := range pol.Rules {
		// Sources must be the backing group.
		if len(rule.Sources) != 1 || rule.Sources[0] != groupID {
			t.Errorf("rule[%d].Sources = %v, want [%s]", i, rule.Sources, groupID)
		}
		// DestinationResource.ID must be the resource ID.
		wantResID := spec.TargetResourceIDs[i]
		if rule.DestinationResource.ID != wantResID {
			t.Errorf("rule[%d].DestinationResource.ID = %q, want %q", i, rule.DestinationResource.ID, wantResID)
		}
		// Action must be accept.
		if rule.Action != types.PolicyTrafficActionAccept {
			t.Errorf("rule[%d].Action = %q, want accept", i, rule.Action)
		}
		// Traffic.
		if string(rule.Protocol) != "tcp" {
			t.Errorf("rule[%d].Protocol = %q, want tcp", i, rule.Protocol)
		}
		if len(rule.Ports) != 1 || rule.Ports[0] != "443" {
			t.Errorf("rule[%d].Ports = %v, want [443]", i, rule.Ports)
		}
		// Not bidirectional.
		if rule.Bidirectional {
			t.Errorf("rule[%d].Bidirectional must be false", i)
		}
	}
}

func TestProvisionBacking_ResourceTypePropagated(t *testing.T) {
	p := newFakeProvisioner(hostResource("h1"), domainResource("d2"))
	spec := basicSpec("pol", "h1", "d2")

	_, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pol := p.policies[policyID]
	if pol.Rules[0].DestinationResource.Type != types.ResourceTypeHost {
		t.Errorf("rule[0] type = %q, want host", pol.Rules[0].DestinationResource.Type)
	}
	if pol.Rules[1].DestinationResource.Type != types.ResourceTypeDomain {
		t.Errorf("rule[1] type = %q, want domain", pol.Rules[1].DestinationResource.Type)
	}
}

// ---------------------------------------------------------------------------
// provisionBacking: rollback on policy-create failure
// ---------------------------------------------------------------------------

func TestProvisionBacking_PolicyCreateFailure_RollsBackGroup(t *testing.T) {
	p := newFakeProvisioner(hostResource("res-1"))
	p.savePolicyErr = errors.New("netbird unavailable")
	spec := basicSpec("pol", "res-1")

	_, _, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// The backing group must have been rolled back.
	if len(p.groups) != 0 {
		t.Errorf("expected no groups after rollback, got %d", len(p.groups))
	}
	if p.deleteGroupCalls != 1 {
		t.Errorf("DeleteGroup called %d times, want 1", p.deleteGroupCalls)
	}
}

func TestProvisionBacking_ResourceLookupFailure_RollsBackGroup(t *testing.T) {
	p := newFakeProvisioner()
	p.getResourcesErr = errors.New("store unavailable")
	spec := basicSpec("pol", "res-1")

	_, _, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Group must be rolled back even when resource lookup fails.
	if len(p.groups) != 0 {
		t.Errorf("expected no groups after rollback, got %d", len(p.groups))
	}
	if p.deleteGroupCalls != 1 {
		t.Errorf("DeleteGroup called %d times, want 1", p.deleteGroupCalls)
	}
}

// ---------------------------------------------------------------------------
// buildPolicy: rule IDs are unique and non-empty (multi-resource policies)
// ---------------------------------------------------------------------------

// TestProvisionBacking_MultiResource_RuleIDsAreUniqueAndNonEmpty guards the
// fix for the PK collision: when a JIT policy targets N>1 resources, every
// produced PolicyRule must carry a distinct, non-empty ID so that
// validatePolicy's "assign policy.ID to empty rule IDs" fallback never fires
// (which would make all rules share the same primary key → store constraint
// violation).
func TestProvisionBacking_MultiResource_RuleIDsAreUniqueAndNonEmpty(t *testing.T) {
	p := newFakeProvisioner(
		hostResource("res-a"),
		hostResource("res-b"),
		domainResource("res-c"),
	)
	spec := basicSpec("multi-pol", "res-a", "res-b", "res-c")

	_, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pol := p.policies[policyID]
	if len(pol.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(pol.Rules))
	}

	seen := make(map[string]struct{}, len(pol.Rules))
	for i, rule := range pol.Rules {
		if rule.ID == "" {
			t.Errorf("rule[%d].ID is empty — would trigger the validatePolicy PK-collision fallback", i)
			continue
		}
		if _, dup := seen[rule.ID]; dup {
			t.Errorf("rule[%d].ID = %q is a duplicate — PK collision would occur on save", i, rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// deprovisionBacking: happy path
// ---------------------------------------------------------------------------

func TestDeprovisionBacking_DeletesPolicyThenGroup(t *testing.T) {
	p := newFakeProvisioner(hostResource("res-1"))

	// Pre-populate a group and a policy in the fake.
	p.groups["grp-1"] = &types.Group{ID: "grp-1", Issued: types.GroupIssuedAPI}
	p.policies["pol-1"] = &types.Policy{ID: "pol-1"}

	err := jit.DeprovisionBacking(context.Background(), p, "acc1", "svc", "grp-1", "pol-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(p.groups) != 0 {
		t.Errorf("expected group deleted, %d remain", len(p.groups))
	}
	if len(p.policies) != 0 {
		t.Errorf("expected policy deleted, %d remain", len(p.policies))
	}

	// Verify order: policy deleted before group.
	if len(p.deletedPolicies) != 1 || p.deletedPolicies[0] != "pol-1" {
		t.Errorf("deletedPolicies = %v, want [pol-1]", p.deletedPolicies)
	}
	if len(p.deletedGroups) != 1 || p.deletedGroups[0] != "grp-1" {
		t.Errorf("deletedGroups = %v, want [grp-1]", p.deletedGroups)
	}
}

// ---------------------------------------------------------------------------
// deprovisionBacking: idempotency on not-found
// ---------------------------------------------------------------------------

func TestDeprovisionBacking_IdempotentOnNotFound(t *testing.T) {
	p := newFakeProvisioner()
	// Neither policy nor group exists — should not error.
	err := jit.DeprovisionBacking(context.Background(), p, "acc1", "svc", "grp-missing", "pol-missing")
	if err != nil {
		t.Fatalf("expected nil error on not-found, got: %v", err)
	}
}

func TestDeprovisionBacking_PolicyAlreadyGone_GroupStillDeleted(t *testing.T) {
	p := newFakeProvisioner()
	p.groups["grp-1"] = &types.Group{ID: "grp-1"}
	// policy doesn't exist — DeletePolicy returns not-found (swallowed).

	err := jit.DeprovisionBacking(context.Background(), p, "acc1", "svc", "grp-1", "pol-missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.groups) != 0 {
		t.Errorf("group must be deleted even when policy is already gone")
	}
}

func TestDeprovisionBacking_GroupAlreadyGone_NoError(t *testing.T) {
	p := newFakeProvisioner()
	p.policies["pol-1"] = &types.Policy{ID: "pol-1"}

	err := jit.DeprovisionBacking(context.Background(), p, "acc1", "svc", "grp-missing", "pol-1")
	if err != nil {
		t.Fatalf("unexpected error when group already gone: %v", err)
	}
	if len(p.policies) != 0 {
		t.Errorf("policy must be deleted even when group is already gone")
	}
}

// ---------------------------------------------------------------------------
// deprovisionBacking: real (non-not-found) errors propagate
// ---------------------------------------------------------------------------

func TestDeprovisionBacking_PolicyDeleteError_Propagates(t *testing.T) {
	p := newFakeProvisioner()
	p.policies["pol-1"] = &types.Policy{ID: "pol-1"}
	p.deletePolicyErr = errors.New("store failure")

	err := jit.DeprovisionBacking(context.Background(), p, "acc1", "svc", "grp-1", "pol-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// updateBackingPolicy
// ---------------------------------------------------------------------------

func TestUpdateBackingPolicy_UpdatesExistingPolicy(t *testing.T) {
	p := newFakeProvisioner(hostResource("res-1"), hostResource("res-2"))

	// Pre-populate existing objects.
	p.groups["grp-1"] = &types.Group{ID: "grp-1", Issued: types.GroupIssuedAPI}
	p.policies["pol-1"] = &types.Policy{ID: "pol-1"}

	jitPol := &types.JitPolicy{
		ID:              "jit-pol-1",
		AccountID:       "acc1",
		Name:            "old-name",
		BackingGroupID:  "grp-1",
		NetbirdPolicyID: "pol-1",
	}
	spec := basicSpec("new-name", "res-1", "res-2")

	err := jit.UpdateBackingPolicy(context.Background(), p, "acc1", "svc", jitPol, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.savePolicyCalls != 1 {
		t.Errorf("SavePolicy called %d times, want 1", p.savePolicyCalls)
	}
	// Policy in fake should be updated (create=false path).
	pol := p.policies["pol-1"]
	if pol == nil {
		t.Fatal("policy pol-1 missing from fake store after update")
	}
	wantName := jit.DefaultMarker + "new-name"
	if pol.Name != wantName {
		t.Errorf("policy name = %q, want %q", pol.Name, wantName)
	}
}

func TestUpdateBackingPolicy_NoOp_WhenNotProvisioned(t *testing.T) {
	p := newFakeProvisioner(hostResource("res-1"))

	jitPol := &types.JitPolicy{
		// BackingGroupID and NetbirdPolicyID both empty.
	}
	err := jit.UpdateBackingPolicy(context.Background(), p, "acc1", "svc", jitPol, basicSpec("pol", "res-1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.savePolicyCalls != 0 {
		t.Errorf("SavePolicy should not be called for unprovisioned policy")
	}
}

// ---------------------------------------------------------------------------
// IsJitOwnedName
// ---------------------------------------------------------------------------

func TestIsJitOwnedName(t *testing.T) {
	tt := []struct {
		name  string
		input string
		want  bool
	}{
		{"marker prefix", jit.DefaultMarker + "my-policy", true},
		{"marker prefix only", jit.DefaultMarker, true},
		{"normal name", "my-policy", false},
		{"empty name", "", false},
		{"partial prefix", "ji", false},
		{"case sensitive no match", "JIT:policy", false},
		{"marker in middle", "prefix-" + jit.DefaultMarker + "policy", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := jit.IsJitOwnedName(tc.input)
			if got != tc.want {
				t.Errorf("IsJitOwnedName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
