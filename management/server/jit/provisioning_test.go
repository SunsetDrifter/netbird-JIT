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
	getPolicyErr    error

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

// GetPolicy looks the policy up in the same map ProvisionBacking writes to;
// tests pre-populate source policies there. Returns a clone so callers can't
// mutate the fake's stored copy.
func (f *fakeProvisioner) GetPolicy(_ context.Context, _, policyID, _ string) (*types.Policy, error) {
	if f.getPolicyErr != nil {
		return nil, f.getPolicyErr
	}
	pol, ok := f.policies[policyID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "policy %s not found", policyID)
	}
	clone := *pol
	return &clone, nil
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

// ---------------------------------------------------------------------------
// provisionBacking: mirror-type (from an existing access-control policy)
// ---------------------------------------------------------------------------

// mirrorSpec returns a policy-based ProvisionSpec (SourcePolicy set, no target
// resources).
func mirrorSpec(name string, src *types.Policy) jit.ProvisionSpec {
	return jit.ProvisionSpec{Name: name, Description: "mirror", SourcePolicy: src}
}

func TestProvisionBacking_FromSourcePolicy_Mirrors(t *testing.T) {
	p := newFakeProvisioner()
	src := &types.Policy{
		ID:   "src-1",
		Name: "Engineers → prod-db",
		Rules: []*types.PolicyRule{
			{
				ID: "r0", Enabled: true, Action: types.PolicyTrafficActionAccept,
				Sources:       []string{"engineers"},
				Destinations:  []string{"g-db"},
				Bidirectional: true,
				Protocol:      "tcp", Ports: []string{"5432"},
			},
			{
				ID: "r1", Enabled: true, Action: types.PolicyTrafficActionAccept,
				SourceResource:      types.Resource{ID: "src-res", Type: types.ResourceTypeHost},
				DestinationResource: types.Resource{ID: "res-x", Type: types.ResourceTypeHost},
				Protocol:            "udp", Ports: []string{"53"},
			},
		},
	}

	groupID, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", mirrorSpec("mir", src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pol := p.policies[policyID]
	if pol == nil {
		t.Fatalf("mirror policy %s not stored", policyID)
	}
	if pol.Name != jit.DefaultMarker+"mir" || !pol.Enabled {
		t.Errorf("policy name/enabled = %q/%v, want %q/true", pol.Name, pol.Enabled, jit.DefaultMarker+"mir")
	}
	if len(pol.Rules) != 2 {
		t.Fatalf("expected 2 mirrored rules, got %d", len(pol.Rules))
	}

	seen := map[string]struct{}{}
	for i, r := range pol.Rules {
		if len(r.Sources) != 1 || r.Sources[0] != groupID {
			t.Errorf("rule[%d].Sources = %v, want [%s] (source side discarded)", i, r.Sources, groupID)
		}
		if r.SourceResource.ID != "" {
			t.Errorf("rule[%d].SourceResource must be cleared, got %q", i, r.SourceResource.ID)
		}
		if r.Bidirectional {
			t.Errorf("rule[%d] must be one-way", i)
		}
		if r.ID == "" {
			t.Errorf("rule[%d].ID must be a fresh non-empty xid", i)
		}
		if _, dup := seen[r.ID]; dup {
			t.Errorf("rule[%d].ID %q duplicated", i, r.ID)
		}
		seen[r.ID] = struct{}{}
		if want := jit.DefaultMarker + "mir-" + itoa(i); r.Name != want {
			t.Errorf("rule[%d].Name = %q, want %q", i, r.Name, want)
		}
	}

	// rule0: group destination + tcp/5432 copied verbatim
	if got := pol.Rules[0].Destinations; len(got) != 1 || got[0] != "g-db" {
		t.Errorf("rule[0].Destinations = %v, want [g-db]", got)
	}
	if string(pol.Rules[0].Protocol) != "tcp" || len(pol.Rules[0].Ports) != 1 || pol.Rules[0].Ports[0] != "5432" {
		t.Errorf("rule[0] traffic = %s/%v, want tcp/[5432]", pol.Rules[0].Protocol, pol.Rules[0].Ports)
	}
	// rule1: resource destination copied verbatim
	if pol.Rules[1].DestinationResource.ID != "res-x" || pol.Rules[1].DestinationResource.Type != types.ResourceTypeHost {
		t.Errorf("rule[1].DestinationResource = %+v, want res-x/host", pol.Rules[1].DestinationResource)
	}
}

func TestProvisionBacking_FromSourcePolicy_CopiesDenyRules(t *testing.T) {
	p := newFakeProvisioner()
	src := &types.Policy{
		ID: "src-1", Name: "subnet with db carve-out",
		Rules: []*types.PolicyRule{
			{ID: "a", Enabled: true, Action: types.PolicyTrafficActionAccept, Destinations: []string{"g-net"}, Protocol: "all"},
			{ID: "d", Enabled: true, Action: types.PolicyTrafficActionDrop, Destinations: []string{"g-db"}, Protocol: "tcp", Ports: []string{"5432"}},
		},
	}

	_, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", mirrorSpec("mir", src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pol := p.policies[policyID]
	if len(pol.Rules) != 2 {
		t.Fatalf("expected accept+drop mirrored, got %d rules", len(pol.Rules))
	}
	var sawAccept, sawDrop bool
	for _, r := range pol.Rules {
		switch r.Action {
		case types.PolicyTrafficActionAccept:
			sawAccept = true
		case types.PolicyTrafficActionDrop:
			sawDrop = true
		}
	}
	if !sawAccept || !sawDrop {
		t.Errorf("deny rule not preserved: sawAccept=%v sawDrop=%v", sawAccept, sawDrop)
	}
}

func TestProvisionBacking_FromSourcePolicy_SkipsDisabledRules(t *testing.T) {
	p := newFakeProvisioner()
	src := &types.Policy{
		ID: "src-1", Name: "mixed",
		Rules: []*types.PolicyRule{
			{ID: "on", Enabled: true, Action: types.PolicyTrafficActionAccept, Destinations: []string{"g-a"}, Protocol: "all"},
			{ID: "off", Enabled: false, Action: types.PolicyTrafficActionAccept, Destinations: []string{"g-b"}, Protocol: "all"},
		},
	}

	_, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", mirrorSpec("mir", src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := len(p.policies[policyID].Rules); got != 1 {
		t.Errorf("expected only the enabled rule mirrored, got %d", got)
	}
}

func TestProvisionBacking_FromSourcePolicy_NoEnabledRules_ErrorsAndRollsBackGroup(t *testing.T) {
	p := newFakeProvisioner()
	src := &types.Policy{
		ID: "src-1", Name: "all-off",
		Rules: []*types.PolicyRule{
			{ID: "off", Enabled: false, Action: types.PolicyTrafficActionAccept, Destinations: []string{"g-a"}},
		},
	}

	_, _, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", mirrorSpec("mir", src))
	if err == nil {
		t.Fatal("expected error for source with no enabled rule")
	}
	if len(p.groups) != 0 || p.deleteGroupCalls != 1 {
		t.Errorf("backing group must be rolled back: groups=%d deleteGroupCalls=%d", len(p.groups), p.deleteGroupCalls)
	}
	if p.savePolicyCalls != 0 {
		t.Errorf("SavePolicy must not be called when there is nothing to mirror")
	}
}

func TestProvisionBacking_FromSourcePolicy_CarriesPostureChecks(t *testing.T) {
	p := newFakeProvisioner()
	src := &types.Policy{
		ID: "src-1", Name: "with-posture",
		SourcePostureChecks: []string{"pc-1", "pc-2"},
		Rules: []*types.PolicyRule{
			{ID: "a", Enabled: true, Action: types.PolicyTrafficActionAccept, Destinations: []string{"g-a"}, Protocol: "all"},
		},
	}

	_, policyID, err := jit.ProvisionBacking(context.Background(), p, "acc1", "svc", mirrorSpec("mir", src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := p.policies[policyID].SourcePostureChecks
	if len(got) != 2 || got[0] != "pc-1" || got[1] != "pc-2" {
		t.Errorf("SourcePostureChecks = %v, want [pc-1 pc-2]", got)
	}
}

// ---------------------------------------------------------------------------
// FingerprintSource
// ---------------------------------------------------------------------------

func TestFingerprintSource_IgnoresSourceSideOrderAndNames(t *testing.T) {
	a := &types.Policy{
		Name: "A", Enabled: true, SourcePostureChecks: []string{"pc-1"},
		Rules: []*types.PolicyRule{
			{ID: "r0", Name: "first", Enabled: true, Action: types.PolicyTrafficActionAccept, Sources: []string{"engineers"}, Destinations: []string{"g-db"}, Protocol: "tcp", Ports: []string{"5432"}},
			{ID: "r1", Name: "second", Enabled: true, Action: types.PolicyTrafficActionDrop, Sources: []string{"ops"}, Destinations: []string{"g-ssh"}, Protocol: "tcp", Ports: []string{"22"}},
		},
	}
	// b: rules reversed, different rule names, different sources/source-resource,
	// policy disabled — none of which change what a mirror would grant.
	b := &types.Policy{
		Name: "B (renamed)", Enabled: false, SourcePostureChecks: []string{"pc-1"},
		Rules: []*types.PolicyRule{
			{ID: "x", Name: "other", Enabled: true, Action: types.PolicyTrafficActionDrop, Sources: []string{"sre"}, SourceResource: types.Resource{ID: "q"}, Destinations: []string{"g-ssh"}, Protocol: "tcp", Ports: []string{"22"}},
			{ID: "y", Name: "another", Enabled: true, Action: types.PolicyTrafficActionAccept, Sources: []string{"anybody"}, Destinations: []string{"g-db"}, Protocol: "tcp", Ports: []string{"5432"}},
		},
	}
	if jit.FingerprintSource(a) != jit.FingerprintSource(b) {
		t.Error("fingerprint must be stable across source-side, order, name, and enabled-flag changes")
	}
}

func TestFingerprintSource_ChangesOnMeaningfulEdits(t *testing.T) {
	base := func() *types.Policy {
		return &types.Policy{
			Name: "base", SourcePostureChecks: []string{"pc-1"},
			Rules: []*types.PolicyRule{
				{ID: "r0", Enabled: true, Action: types.PolicyTrafficActionAccept, Destinations: []string{"g-db"}, Protocol: "tcp", Ports: []string{"5432"}},
			},
		}
	}
	baseFP := jit.FingerprintSource(base())

	cases := map[string]func(*types.Policy){
		"port":        func(p *types.Policy) { p.Rules[0].Ports = []string{"5433"} },
		"destination": func(p *types.Policy) { p.Rules[0].Destinations = []string{"g-other"} },
		"action":      func(p *types.Policy) { p.Rules[0].Action = types.PolicyTrafficActionDrop },
		"protocol":    func(p *types.Policy) { p.Rules[0].Protocol = "udp" },
		"posture":     func(p *types.Policy) { p.SourcePostureChecks = []string{"pc-1", "pc-2"} },
		"newRule":     func(p *types.Policy) { p.Rules = append(p.Rules, &types.PolicyRule{ID: "r1", Enabled: true, Action: types.PolicyTrafficActionAccept, Destinations: []string{"g-x"}, Protocol: "all"}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(p)
			if jit.FingerprintSource(p) == baseFP {
				t.Errorf("fingerprint must change when %s changes", name)
			}
		})
	}
}

func TestFingerprintSource_NilIsEmpty(t *testing.T) {
	if jit.FingerprintSource(nil) != "" {
		t.Error("nil policy must fingerprint to empty string")
	}
}

// itoa is a tiny helper so the test file needs no extra import.
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
