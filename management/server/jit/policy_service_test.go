package jit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/jit"
)

// ---------------------------------------------------------------------------
// Fakes shared across jit package tests
// ---------------------------------------------------------------------------

// fakeStore is a map-backed implementation of jit.Store for unit tests.
//
// Policy methods are fully exercised by Task 6's policy-service tests. Grant
// methods are present so the type satisfies the whole jit.Store interface, but
// they are intentionally minimal here — Task 7 (grant service) extends their
// behaviour. Each grant method records that it was called so future tests can
// assert wiring without re-deriving the fake.
type fakeStore struct {
	mu sync.Mutex // guards grants for the -race concurrent-extend test

	policies map[string]*types.JitPolicy // policyID → policy
	grants   map[string]*types.JitGrant  // grantID → grant

	// Error injection for policy persistence paths used by Task 6.
	saveErr   error
	deleteErr error

	// saveErrAfter, when > 0, makes SaveJitPolicy succeed for the first N calls
	// and then return saveErrAfterErr on every subsequent call. This lets tests
	// simulate a write-back (step-3) failure after provisioning has succeeded.
	saveErrAfter    int
	saveErrAfterErr error
	saveCallCount   int

	// onDeletePolicy fires inside DeleteJitPolicy so ordering tests can record
	// when the row delete happened relative to other deps.
	onDeletePolicy func()

	// Call log for ordering / wiring assertions.
	calls []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		policies: make(map[string]*types.JitPolicy),
		grants:   make(map[string]*types.JitGrant),
	}
}

// record appends to the call log. Callers MUST hold f.mu (every store method
// below takes it), so record stays lock-free to avoid re-entrant locking.
func (f *fakeStore) record(name string) { f.calls = append(f.calls, name) }

// --- JIT policy methods (exercised) ---

func (f *fakeStore) SaveJitPolicy(_ context.Context, policy *types.JitPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SaveJitPolicy")
	f.saveCallCount++
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.saveErrAfter > 0 && f.saveCallCount > f.saveErrAfter {
		return f.saveErrAfterErr
	}
	// Store a copy so callers can't mutate persisted state by reference.
	clone := *policy
	f.policies[policy.ID] = &clone
	return nil
}

func (f *fakeStore) GetJitPolicyByID(_ context.Context, accountID, policyID string) (*types.JitPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetJitPolicyByID")
	p, ok := f.policies[policyID]
	if !ok || p.AccountID != accountID {
		return nil, errNotFound
	}
	clone := *p
	return &clone, nil
}

func (f *fakeStore) ListJitPolicies(_ context.Context, accountID string) ([]*types.JitPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListJitPolicies")
	out := make([]*types.JitPolicy, 0, len(f.policies))
	for _, p := range f.policies {
		if p.AccountID == accountID {
			clone := *p
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (f *fakeStore) DeleteJitPolicy(_ context.Context, accountID, policyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DeleteJitPolicy")
	if f.onDeletePolicy != nil {
		f.onDeletePolicy()
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	p, ok := f.policies[policyID]
	if !ok || p.AccountID != accountID {
		return errNotFound
	}
	delete(f.policies, policyID)
	return nil
}

// --- JIT grant methods (functional; exercised by Task 7) ---
//
// These are map-backed and concurrency-safe so the grant-service tests can
// drive the full lifecycle and the compare-and-set atomicity of
// TransitionJitGrantStatus. A package-level mutex serializes all access (the
// grant service issues no concurrent reads on the same fake outside the
// CAS-claim tests, but the lock keeps -race clean there).

func (f *fakeStore) CreateJitGrant(_ context.Context, grant *types.JitGrant) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateJitGrant")
	clone := *grant
	f.grants[grant.ID] = &clone
	return nil
}

func (f *fakeStore) GetJitGrantByID(_ context.Context, accountID, grantID string) (*types.JitGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetJitGrantByID")
	g, ok := f.grants[grantID]
	if !ok || g.AccountID != accountID {
		return nil, errNotFound
	}
	clone := *g
	return &clone, nil
}

func (f *fakeStore) ListJitGrantsByRequester(_ context.Context, accountID, requesterUserID string) ([]*types.JitGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListJitGrantsByRequester")
	var out []*types.JitGrant
	for _, g := range f.grants {
		if g.AccountID == accountID && g.RequesterUserID == requesterUserID {
			clone := *g
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (f *fakeStore) ListJitGrantsByAccount(_ context.Context, accountID string, grantStatus types.GrantStatus) ([]*types.JitGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListJitGrantsByAccount")
	var out []*types.JitGrant
	for _, g := range f.grants {
		if g.AccountID != accountID {
			continue
		}
		if grantStatus != "" && g.Status != grantStatus {
			continue
		}
		clone := *g
		out = append(out, &clone)
	}
	return out, nil
}

func (f *fakeStore) GetActiveJitGrantFor(_ context.Context, accountID, requesterUserID, policyID string) (*types.JitGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetActiveJitGrantFor")
	for _, g := range f.grants {
		if g.AccountID == accountID && g.RequesterUserID == requesterUserID &&
			g.PolicyID == policyID && g.Status == types.GrantStatusActive {
			clone := *g
			return &clone, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) ListActiveJitGrantsExpiringBefore(_ context.Context, threshold time.Time) ([]*types.JitGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListActiveJitGrantsExpiringBefore")
	var out []*types.JitGrant
	for _, g := range f.grants {
		if g.Status == types.GrantStatusActive && g.ExpiresAt != nil && g.ExpiresAt.Before(threshold) {
			clone := *g
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (f *fakeStore) ListPendingJitGrantsExpiringBefore(_ context.Context, threshold time.Time) ([]*types.JitGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListPendingJitGrantsExpiringBefore")
	var out []*types.JitGrant
	for _, g := range f.grants {
		if g.Status == types.GrantStatusPending && g.PendingExpiresAt != nil && g.PendingExpiresAt.Before(threshold) {
			clone := *g
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (f *fakeStore) ListFailedJitGrants(_ context.Context) ([]*types.JitGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListFailedJitGrants")
	var out []*types.JitGrant
	for _, g := range f.grants {
		if g.Status == types.GrantStatusFailed {
			clone := *g
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (f *fakeStore) ActiveGrantUserIDsForPolicy(_ context.Context, accountID, policyID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ActiveGrantUserIDsForPolicy")
	var out []string
	for _, g := range f.grants {
		if g.AccountID == accountID && g.PolicyID == policyID && g.Status == types.GrantStatusActive {
			out = append(out, g.RequesterUserID)
		}
	}
	return out, nil
}

// TransitionJitGrantStatus is a compare-and-set: it only mutates the row when
// its current status equals from, mirroring the SqlStore WHERE clause. Patch
// fields are applied to the stored copy (non-nil only).
func (f *fakeStore) TransitionJitGrantStatus(_ context.Context, grantID string, from, to types.GrantStatus, patch types.JitGrantPatch) (*types.JitGrant, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("TransitionJitGrantStatus")
	g, ok := f.grants[grantID]
	if !ok {
		return nil, false, errNotFound
	}
	if g.Status != from {
		return nil, false, nil // lost the CAS race
	}
	updated := *g
	updated.Status = to
	applyGrantPatch(&updated, patch)
	f.grants[grantID] = &updated
	clone := updated
	return &clone, true, nil
}

// applyGrantPatch copies the non-nil patch fields onto the grant (test mirror
// of buildJitGrantUpdates in the SqlStore).
func applyGrantPatch(g *types.JitGrant, patch types.JitGrantPatch) {
	if patch.ApproverUserID != nil {
		g.ApproverUserID = patch.ApproverUserID
	}
	if patch.ApproverEmail != nil {
		g.ApproverEmail = patch.ApproverEmail
	}
	if patch.DenialReason != nil {
		g.DenialReason = patch.DenialReason
	}
	if patch.RevokeReason != nil {
		g.RevokeReason = patch.RevokeReason
	}
	if patch.DecidedAt != nil {
		g.DecidedAt = patch.DecidedAt
	}
	if patch.ActivatedAt != nil {
		g.ActivatedAt = patch.ActivatedAt
	}
	if patch.ExpiresAt != nil {
		g.ExpiresAt = patch.ExpiresAt
	}
	if patch.RevokedAt != nil {
		g.RevokedAt = patch.RevokedAt
	}
	if patch.LastError != nil {
		g.LastError = patch.LastError
	}
}

// allGrants returns a snapshot copy of every stored grant (for invariant
// assertions in tests).
func (f *fakeStore) allGrants() []*types.JitGrant {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.JitGrant, 0, len(f.grants))
	for _, g := range f.grants {
		clone := *g
		out = append(out, &clone)
	}
	return out
}

var errNotFound = errors.New("not found")

// ---------------------------------------------------------------------------
// Fake event emitter
// ---------------------------------------------------------------------------

type storedEvent struct {
	initiatorID string
	targetID    string
	accountID   string
	activity    activity.ActivityDescriber
	meta        map[string]any
}

type fakeEvents struct {
	mu     sync.Mutex // guards events for the -race concurrent-extend test
	events []storedEvent
}

func (f *fakeEvents) StoreEvent(_ context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, storedEvent{initiatorID, targetID, accountID, activityID, meta})
}

func (f *fakeEvents) only() storedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) != 1 {
		panic("expected exactly one event")
	}
	return f.events[0]
}

// ---------------------------------------------------------------------------
// Fake grant canceller (Task 7 implements the real one)
// ---------------------------------------------------------------------------

type fakeGrantCanceller struct {
	calls  int
	lastID string
	reason string
	err    error
	// hook lets the delete-ordering test record interleaving with other deps.
	onCall func()
}

func (f *fakeGrantCanceller) TerminateGrantsForPolicy(_ context.Context, _, policyID, reason string) error {
	f.calls++
	f.lastID = policyID
	f.reason = reason
	if f.onCall != nil {
		f.onCall()
	}
	return f.err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const (
	testAccountID = "acct-1"
	testUserID    = "user-1"
)

func newTestManager(t *testing.T) (*jit.Manager, *fakeStore, *fakeProvisioner, *fakeEvents, *fakeGrantCanceller) {
	t.Helper()
	store := newFakeStore()
	prov := newFakeProvisioner()
	events := &fakeEvents{}
	grants := &fakeGrantCanceller{}
	account := newFakeAccount()
	// A non-nil fake grantCanceller is injected so the policy delete-cascade
	// tests can assert TerminateGrantsForPolicy is invoked; when nil is passed
	// (production / grant-service tests) the manager self-wires as its own
	// canceller.
	m := jit.NewManager(store, prov, events, account, grants, jit.DefaultMarker, 1440)
	return m, store, prov, events, grants
}

func validCreateInput() jit.CreateJitPolicyInput {
	return jit.CreateJitPolicyInput{
		Name:               "db-admin",
		Description:        "Database admin access",
		TargetResourceIDs:  []string{"res-1"},
		Traffic:            &types.JitTraffic{Protocol: "tcp", Ports: []string{"5432"}},
		MaxDurationMinutes: 60,
		RequestableBy:      types.JitRequestableBy{Mode: "all"},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
	}
}

// ---------------------------------------------------------------------------
// CreatePolicy
// ---------------------------------------------------------------------------

func TestCreatePolicy_PersistsProvisionsAndEmits(t *testing.T) {
	m, store, prov, events, _ := newTestManager(t)

	out, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// Row persisted under the right account, enabled, with a generated id.
	if out.ID == "" {
		t.Fatal("expected a generated policy ID")
	}
	if out.AccountID != testAccountID {
		t.Errorf("AccountID = %q, want %q", out.AccountID, testAccountID)
	}
	if !out.Enabled {
		t.Error("new policy should be Enabled")
	}
	if got := store.policies[out.ID]; got == nil {
		t.Fatal("policy not persisted in store")
	}

	// Backing IDs written back from provisioning.
	if out.BackingGroupID == "" || out.NetbirdPolicyID == "" {
		t.Errorf("backing IDs not written back: group=%q policy=%q", out.BackingGroupID, out.NetbirdPolicyID)
	}
	if store.policies[out.ID].BackingGroupID != out.BackingGroupID {
		t.Error("persisted row missing backing group ID")
	}
	if store.policies[out.ID].NetbirdPolicyID != out.NetbirdPolicyID {
		t.Error("persisted row missing netbird policy ID")
	}

	// Provisioning actually ran.
	if prov.createGroupCalls != 1 {
		t.Errorf("createGroupCalls = %d, want 1", prov.createGroupCalls)
	}
	if prov.savePolicyCalls != 1 {
		t.Errorf("savePolicyCalls = %d, want 1", prov.savePolicyCalls)
	}

	// JitPolicyCreated emitted with the new policy as target.
	ev := events.only()
	if ev.activity != activity.JitPolicyCreated {
		t.Errorf("activity = %v, want JitPolicyCreated", ev.activity)
	}
	if ev.accountID != testAccountID || ev.initiatorID != testUserID {
		t.Errorf("event scoping wrong: account=%q initiator=%q", ev.accountID, ev.initiatorID)
	}
	if ev.targetID != out.ID {
		t.Errorf("event targetID = %q, want policy id %q", ev.targetID, out.ID)
	}
}

func TestCreatePolicy_DefaultsTrafficAndPendingTTL(t *testing.T) {
	m, _, _, _, _ := newTestManager(t)

	in := validCreateInput()
	in.Traffic = nil           // omitted → default {protocol: all}
	in.PendingTTLMinutes = nil // omitted → manager default (1440)

	out, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, in)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if out.Traffic.Protocol != "all" {
		t.Errorf("default traffic protocol = %q, want all", out.Traffic.Protocol)
	}
	if out.PendingTTLMinutes != 1440 {
		t.Errorf("default pending TTL = %d, want 1440", out.PendingTTLMinutes)
	}
}

func TestCreatePolicy_RollsBackRowOnProvisioningFailure(t *testing.T) {
	m, store, prov, events, _ := newTestManager(t)
	prov.savePolicyErr = errors.New("netbird boom") // provisioning fails at policy creation

	_, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err == nil {
		t.Fatal("expected error when provisioning fails")
	}

	// The persisted draft row must be gone (rollback).
	if len(store.policies) != 0 {
		t.Errorf("expected row rolled back, found %d policies", len(store.policies))
	}
	// No JitPolicyCreated event on failure.
	if len(events.events) != 0 {
		t.Errorf("expected no events on failure, got %d", len(events.events))
	}
	// DeleteJitPolicy was invoked as part of rollback.
	if !contains(store.calls, "DeleteJitPolicy") {
		t.Errorf("rollback did not call DeleteJitPolicy; calls=%v", store.calls)
	}
}

func TestCreatePolicy_RollsBackRowAndBackingOnWriteBackFailure(t *testing.T) {
	m, store, prov, events, _ := newTestManager(t)

	// The first SaveJitPolicy call (step-1 persist) must succeed; the second
	// (step-3 write-back) must fail so provisioning has already completed.
	store.saveErrAfter = 1
	store.saveErrAfterErr = errors.New("db write-back boom")

	_, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err == nil {
		t.Fatal("expected error when write-back fails")
	}

	// The policy row must be gone — rollback deleted it.
	if len(store.policies) != 0 {
		t.Errorf("expected row rolled back, found %d policies", len(store.policies))
	}

	// The backing objects (group + NetBird policy) created in step-2 must have
	// been deprovisioned — otherwise they are permanently orphaned.
	if prov.deleteGroupCalls != 1 {
		t.Errorf("deleteGroupCalls = %d, want 1 (backing group must be cleaned up)", prov.deleteGroupCalls)
	}
	if prov.deletePolicyCalls != 1 {
		t.Errorf("deletePolicyCalls = %d, want 1 (backing NetBird policy must be cleaned up)", prov.deletePolicyCalls)
	}

	// No JitPolicyCreated event must be emitted on failure.
	if len(events.events) != 0 {
		t.Errorf("expected no events on failure, got %d", len(events.events))
	}
}

// ---------------------------------------------------------------------------
// UpdatePolicy
// ---------------------------------------------------------------------------

func TestUpdatePolicy_ResyncsBackingPolicyAndEmits(t *testing.T) {
	m, _, prov, events, _ := newTestManager(t)

	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed CreatePolicy: %v", err)
	}
	savePolicyCallsAfterCreate := prov.savePolicyCalls
	events.events = nil // reset to isolate the update event

	newResources := []string{"res-1", "res-2"}
	patch := jit.UpdateJitPolicyInput{TargetResourceIDs: &newResources}
	out, err := m.UpdatePolicy(context.Background(), testAccountID, testUserID, created.ID, patch)
	if err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}

	if len(out.TargetResourceIDs) != 2 {
		t.Errorf("resources not updated: %v", out.TargetResourceIDs)
	}
	// Backing policy re-synced (one extra SavePolicy beyond create).
	if prov.savePolicyCalls != savePolicyCallsAfterCreate+1 {
		t.Errorf("expected backing policy re-sync; savePolicyCalls=%d", prov.savePolicyCalls)
	}
	ev := events.only()
	if ev.activity != activity.JitPolicyUpdated {
		t.Errorf("activity = %v, want JitPolicyUpdated", ev.activity)
	}
	if ev.targetID != created.ID {
		t.Errorf("event targetID = %q, want %q", ev.targetID, created.ID)
	}
}

func TestUpdatePolicy_NoResyncWhenPolicyShapeUnchanged(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)

	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := prov.savePolicyCalls

	// Patch a field that does NOT affect the backing policy (maxDuration).
	dur := 120
	patch := jit.UpdateJitPolicyInput{MaxDurationMinutes: &dur}
	if _, err := m.UpdatePolicy(context.Background(), testAccountID, testUserID, created.ID, patch); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if prov.savePolicyCalls != before {
		t.Errorf("expected no backing re-sync; savePolicyCalls went %d→%d", before, prov.savePolicyCalls)
	}
}

func TestUpdatePolicy_AccountScoped(t *testing.T) {
	m, _, _, _, _ := newTestManager(t)
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	name := "x"
	patch := jit.UpdateJitPolicyInput{Name: &name}
	if _, err := m.UpdatePolicy(context.Background(), "other-account", testUserID, created.ID, patch); err == nil {
		t.Fatal("expected error updating a policy from another account")
	}
}

// ---------------------------------------------------------------------------
// DeletePolicy
// ---------------------------------------------------------------------------

func TestDeletePolicy_CascadeOrderAndEmits(t *testing.T) {
	m, store, prov, events, grants := newTestManager(t)

	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	events.events = nil

	// Record global ordering across deps: grant cancellation, deprovision
	// (DeleteGroup / DeletePolicy on provisioner), then row delete.
	var order []string
	grants.onCall = func() { order = append(order, "terminate") }
	prov.onDeletePolicy = func() { order = append(order, "deprovision-policy") }
	prov.onDeleteGroup = func() { order = append(order, "deprovision-group") }
	store.onDeletePolicy = func() { order = append(order, "delete-row") }

	if err := m.DeletePolicy(context.Background(), testAccountID, testUserID, created.ID); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}

	// Grant cancellation called once, with the right policy + reason.
	if grants.calls != 1 {
		t.Errorf("TerminateGrantsForPolicy calls = %d, want 1", grants.calls)
	}
	if grants.lastID != created.ID {
		t.Errorf("terminate policyID = %q, want %q", grants.lastID, created.ID)
	}
	if grants.reason == "" {
		t.Error("terminate reason should be non-empty")
	}

	// Ordering: terminate FIRST, deprovision NEXT, row delete LAST.
	if len(order) < 3 {
		t.Fatalf("expected terminate→deprovision→delete-row, got %v", order)
	}
	if order[0] != "terminate" {
		t.Errorf("first op = %q, want terminate; order=%v", order[0], order)
	}
	if last := order[len(order)-1]; last != "delete-row" {
		t.Errorf("last op = %q, want delete-row; order=%v", last, order)
	}
	// Every deprovision op must come after terminate and before delete-row.
	terminateIdx := indexOf(order, "terminate")
	rowIdx := indexOf(order, "delete-row")
	for i, op := range order {
		if op == "deprovision-policy" || op == "deprovision-group" {
			if i < terminateIdx {
				t.Errorf("%s ran before terminate; order=%v", op, order)
			}
			if i > rowIdx {
				t.Errorf("%s ran after row delete; order=%v", op, order)
			}
		}
	}

	// Row gone, event emitted.
	if len(store.policies) != 0 {
		t.Errorf("policy row not deleted; %d remain", len(store.policies))
	}
	ev := events.only()
	if ev.activity != activity.JitPolicyDeleted {
		t.Errorf("activity = %v, want JitPolicyDeleted", ev.activity)
	}
	if ev.targetID != created.ID {
		t.Errorf("event targetID = %q, want %q", ev.targetID, created.ID)
	}
}

func TestDeletePolicy_StopsWhenGrantTerminationFails(t *testing.T) {
	m, store, prov, _, grants := newTestManager(t)
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	grants.err = errors.New("cannot void grants")
	deprovBefore := prov.deletePolicyCalls + prov.deleteGroupCalls

	if err := m.DeletePolicy(context.Background(), testAccountID, testUserID, created.ID); err == nil {
		t.Fatal("expected error when grant termination fails")
	}
	// Fail-closed: do not deprovision or delete the row if grants can't be voided.
	if prov.deletePolicyCalls+prov.deleteGroupCalls != deprovBefore {
		t.Error("deprovision ran despite grant termination failure")
	}
	if len(store.policies) != 1 {
		t.Error("policy row deleted despite grant termination failure")
	}
}

func TestDeletePolicy_AccountScoped(t *testing.T) {
	m, _, _, _, grants := newTestManager(t)
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.DeletePolicy(context.Background(), "other-account", testUserID, created.ID); err == nil {
		t.Fatal("expected error deleting a policy from another account")
	}
	if grants.calls != 0 {
		t.Error("should not terminate grants for a policy in another account")
	}
}

// ---------------------------------------------------------------------------
// Get / List
// ---------------------------------------------------------------------------

func TestGetAndListPolicies_AccountScoped(t *testing.T) {
	m, _, _, _, _ := newTestManager(t)

	a, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	in := validCreateInput()
	in.Name = "other-acct-policy"
	if _, err := m.CreatePolicy(context.Background(), "other-account", testUserID, in); err != nil {
		t.Fatalf("seed other: %v", err)
	}

	// Get is account-scoped.
	got, err := m.GetPolicy(context.Background(), testAccountID, a.ID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.ID != a.ID {
		t.Errorf("GetPolicy returned %q, want %q", got.ID, a.ID)
	}
	if _, err := m.GetPolicy(context.Background(), "other-account", a.ID); err == nil {
		t.Error("GetPolicy should be account-scoped")
	}

	// List is account-scoped.
	list, err := m.ListPolicies(context.Background(), testAccountID)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(list) != 1 || list[0].ID != a.ID {
		t.Errorf("ListPolicies = %v, want only %q", list, a.ID)
	}
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// Mirror-type policies (based on an existing access-control policy)
// ---------------------------------------------------------------------------

// seedSource registers a source access-control policy in the provisioner fake
// so the manager's GetPolicy reads it back.
func seedSource(prov *fakeProvisioner, id, name string, rules ...*types.PolicyRule) *types.Policy {
	p := &types.Policy{ID: id, AccountID: testAccountID, Name: name, Enabled: true, Rules: rules}
	prov.policies[id] = p
	return p
}

func acceptRule(dest string, ports ...string) *types.PolicyRule {
	return &types.PolicyRule{
		ID: "r-" + dest, Enabled: true, Action: types.PolicyTrafficActionAccept,
		Destinations: []string{dest}, Protocol: "tcp", Ports: ports,
	}
}

func mirrorCreateInput(sourcePolicyID string) jit.CreateJitPolicyInput {
	return jit.CreateJitPolicyInput{
		Name:               "mirror-pol",
		Description:        "from policy",
		SourcePolicyID:     sourcePolicyID,
		MaxDurationMinutes: 60,
		RequestableBy:      types.JitRequestableBy{Mode: "all"},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
	}
}

func TestCreatePolicy_MirrorType_SnapshotsSourceAndProvisions(t *testing.T) {
	m, store, prov, events, _ := newTestManager(t)
	src := seedSource(prov, "src-1", "Engineers → prod-db", acceptRule("g-db", "5432"))

	out, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("src-1"))
	if err != nil {
		t.Fatalf("CreatePolicy(mirror): %v", err)
	}
	if out.SourcePolicyID != "src-1" {
		t.Errorf("SourcePolicyID = %q, want src-1", out.SourcePolicyID)
	}
	if out.SourcePolicyName != "Engineers → prod-db" {
		t.Errorf("SourcePolicyName = %q, want the source's name", out.SourcePolicyName)
	}
	if out.SourceFingerprint == "" || out.SourceFingerprint != jit.FingerprintSource(src) {
		t.Errorf("SourceFingerprint = %q, want FingerprintSource(src)", out.SourceFingerprint)
	}
	if len(out.TargetResourceIDs) != 0 {
		t.Errorf("mirror-type must carry no target resources, got %v", out.TargetResourceIDs)
	}
	if out.BackingGroupID == "" || out.NetbirdPolicyID == "" {
		t.Errorf("backing IDs not written back: %q/%q", out.BackingGroupID, out.NetbirdPolicyID)
	}
	if store.policies[out.ID].SourceFingerprint != out.SourceFingerprint {
		t.Error("persisted row missing source fingerprint")
	}
	if ev := events.only(); ev.activity != activity.JitPolicyCreated {
		t.Errorf("activity = %v, want JitPolicyCreated", ev.activity)
	}
}

func TestCreatePolicy_RejectsBothSourceAndResources(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)
	seedSource(prov, "src-1", "p", acceptRule("g", "1"))
	in := mirrorCreateInput("src-1")
	in.TargetResourceIDs = []string{"res-1"} // both set
	if _, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, in); err == nil {
		t.Fatal("expected error when both sourcePolicyId and targetResourceIds are set")
	}
}

func TestCreatePolicy_RejectsNeitherSourceNorResources(t *testing.T) {
	m, _, _, _, _ := newTestManager(t)
	in := validCreateInput()
	in.TargetResourceIDs = nil // neither set
	if _, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, in); err == nil {
		t.Fatal("expected error when neither sourcePolicyId nor targetResourceIds is set")
	}
}

func TestCreatePolicy_RejectsJitOwnedSource(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)
	seedSource(prov, "jit-src", jit.DefaultMarker+"some-jit-policy", acceptRule("g", "1"))
	if _, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("jit-src")); err == nil {
		t.Fatal("expected error basing a JIT policy on a JIT-owned policy")
	}
}

func TestCreatePolicy_RejectsMissingSource(t *testing.T) {
	m, _, _, _, _ := newTestManager(t)
	if _, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("does-not-exist")); err == nil {
		t.Fatal("expected error when the source policy does not exist")
	}
}

func TestUpdatePolicy_ResyncMirror_RefreshesFingerprintAndRebuilds(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)
	seedSource(prov, "src-1", "src", acceptRule("g-db", "5432"))
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("src-1"))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := created.SourceFingerprint
	saveCallsAfterCreate := prov.savePolicyCalls

	// Source drifts: add a port.
	prov.policies["src-1"].Rules[0].Ports = []string{"5432", "8080"}

	srcID := "src-1"
	out, err := m.UpdatePolicy(context.Background(), testAccountID, testUserID, created.ID, jit.UpdateJitPolicyInput{SourcePolicyID: &srcID})
	if err != nil {
		t.Fatalf("re-sync: %v", err)
	}
	if out.SourceFingerprint == before {
		t.Error("re-sync must refresh the fingerprint to the current source")
	}
	if prov.savePolicyCalls != saveCallsAfterCreate+1 {
		t.Errorf("re-sync must rebuild the backing policy once; savePolicyCalls=%d want %d", prov.savePolicyCalls, saveCallsAfterCreate+1)
	}
}

func TestUpdatePolicy_RepointMirror_ToDifferentSource(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)
	seedSource(prov, "src-1", "first", acceptRule("g-a", "1"))
	seedSource(prov, "src-2", "second", acceptRule("g-b", "2"))
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("src-1"))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	srcID := "src-2"
	out, err := m.UpdatePolicy(context.Background(), testAccountID, testUserID, created.ID, jit.UpdateJitPolicyInput{SourcePolicyID: &srcID})
	if err != nil {
		t.Fatalf("re-point: %v", err)
	}
	if out.SourcePolicyID != "src-2" || out.SourcePolicyName != "second" {
		t.Errorf("re-point got %q/%q, want src-2/second", out.SourcePolicyID, out.SourcePolicyName)
	}
}

func TestUpdatePolicy_RejectsConvertMirrorToResource(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)
	seedSource(prov, "src-1", "src", acceptRule("g", "1"))
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("src-1"))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	res := []string{"res-9"}
	if _, err := m.UpdatePolicy(context.Background(), testAccountID, testUserID, created.ID, jit.UpdateJitPolicyInput{TargetResourceIDs: &res}); err == nil {
		t.Fatal("expected error setting targetResourceIds on a mirror-type policy")
	}
}

func TestUpdatePolicy_RejectsConvertResourceToMirror(t *testing.T) {
	m, _, _, _, _ := newTestManager(t)
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	srcID := "src-1"
	if _, err := m.UpdatePolicy(context.Background(), testAccountID, testUserID, created.ID, jit.UpdateJitPolicyInput{SourcePolicyID: &srcID}); err == nil {
		t.Fatal("expected error setting sourcePolicyId on a resource-based policy")
	}
}

func TestUpdatePolicy_MirrorRename_DoesNotRebuildBacking(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)
	seedSource(prov, "src-1", "src", acceptRule("g", "1"))
	created, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("src-1"))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := prov.savePolicyCalls
	name := "renamed"
	if _, err := m.UpdatePolicy(context.Background(), testAccountID, testUserID, created.ID, jit.UpdateJitPolicyInput{Name: &name}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if prov.savePolicyCalls != before {
		t.Errorf("mirror rename must not rebuild the backing policy; savePolicyCalls %d→%d", before, prov.savePolicyCalls)
	}
}

func TestSourceDriftStatus(t *testing.T) {
	m, _, prov, _, _ := newTestManager(t)

	// resource-based → never drifts.
	res, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, validCreateInput())
	if err != nil {
		t.Fatalf("seed resource policy: %v", err)
	}
	if d, del := m.SourceDriftStatus(context.Background(), testAccountID, testUserID, res); d || del {
		t.Errorf("resource-based drift = %v/%v, want false/false", d, del)
	}

	seedSource(prov, "src-1", "src", acceptRule("g-db", "5432"))
	mir, err := m.CreatePolicy(context.Background(), testAccountID, testUserID, mirrorCreateInput("src-1"))
	if err != nil {
		t.Fatalf("seed mirror policy: %v", err)
	}

	// unchanged → no drift.
	if d, del := m.SourceDriftStatus(context.Background(), testAccountID, testUserID, mir); d || del {
		t.Errorf("unchanged drift = %v/%v, want false/false", d, del)
	}

	// source changed → drifted.
	prov.policies["src-1"].Rules[0].Ports = []string{"9999"}
	if d, del := m.SourceDriftStatus(context.Background(), testAccountID, testUserID, mir); !d || del {
		t.Errorf("changed-source drift = %v/%v, want true/false", d, del)
	}

	// source deleted → deleted.
	delete(prov.policies, "src-1")
	if d, del := m.SourceDriftStatus(context.Background(), testAccountID, testUserID, mir); d || !del {
		t.Errorf("deleted-source drift = %v/%v, want false/true", d, del)
	}
}
