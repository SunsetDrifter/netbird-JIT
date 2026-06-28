package jit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/types"
)

// ---------------------------------------------------------------------------
// Helpers: seed grants with controlled timestamps
// ---------------------------------------------------------------------------

// pastTime returns a time `d` before the fixed sweep `now`.
func pastTime(d time.Duration) time.Time {
	return fixedNow.Add(-d)
}

// futureTime returns a time `d` after the fixed sweep `now`.
func futureTime(d time.Duration) time.Time {
	return fixedNow.Add(d)
}

// fixedNow is the controlled "now" injected into SweepOnce for deterministic tests.
var fixedNow = time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)

// seedActiveGrant inserts a directly-active grant into the store with a
// controlled ExpiresAt so the sweep tests can place grants precisely
// before/after the sweep threshold.
func seedActiveGrant(t *testing.T, store *fakeStore, id, policyID, userID string, expiresAt time.Time) *types.JitGrant {
	t.Helper()
	now := time.Now().UTC()
	g := &types.JitGrant{
		ID:                       id,
		AccountID:                testAccountID,
		PolicyID:                 policyID,
		RequesterUserID:          userID,
		RequestedDurationMinutes: 60,
		Status:                   types.GrantStatusActive,
		RequestedAt:              now,
		ActivatedAt:              &now,
		ExpiresAt:                &expiresAt,
	}
	if err := store.CreateJitGrant(context.Background(), g); err != nil {
		t.Fatalf("seedActiveGrant %s: %v", id, err)
	}
	return g
}

// seedPendingGrant inserts a pending grant with a controlled PendingExpiresAt.
func seedPendingGrant(t *testing.T, store *fakeStore, id, policyID, userID string, pendingExpiresAt time.Time) *types.JitGrant {
	t.Helper()
	now := time.Now().UTC()
	g := &types.JitGrant{
		ID:                       id,
		AccountID:                testAccountID,
		PolicyID:                 policyID,
		RequesterUserID:          userID,
		RequestedDurationMinutes: 60,
		Status:                   types.GrantStatusPending,
		RequestedAt:              now,
		PendingExpiresAt:         &pendingExpiresAt,
	}
	if err := store.CreateJitGrant(context.Background(), g); err != nil {
		t.Fatalf("seedPendingGrant %s: %v", id, err)
	}
	return g
}

// seedFailedGrant inserts a failed grant (membership apply failed at approve).
func seedFailedGrant(t *testing.T, store *fakeStore, id, policyID, userID string) *types.JitGrant {
	t.Helper()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	lastErr := "netbird unavailable"
	g := &types.JitGrant{
		ID:                       id,
		AccountID:                testAccountID,
		PolicyID:                 policyID,
		RequesterUserID:          userID,
		RequestedDurationMinutes: 60,
		Status:                   types.GrantStatusFailed,
		RequestedAt:              now,
		ActivatedAt:              &now,
		ExpiresAt:                &exp,
		LastError:                &lastErr,
	}
	if err := store.CreateJitGrant(context.Background(), g); err != nil {
		t.Fatalf("seedFailedGrant %s: %v", id, err)
	}
	return g
}

// ---------------------------------------------------------------------------
// SweepOnce: active grant expiry
// ---------------------------------------------------------------------------

func TestSweepOnce_ExpiresOverdueActiveGrant(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	_ = seedGrantPolicy(t, store)

	// Grant expired 5 minutes ago — must be swept.
	seedActiveGrant(t, store, "g-past", "pol-1", "u1", pastTime(5*time.Minute))
	// Grant expires 5 minutes from now — must NOT be swept.
	seedActiveGrant(t, store, "g-future", "pol-1", "u2", futureTime(5*time.Minute))

	if err := m.SweepOnce(context.Background(), fixedNow); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}

	pastGrant, _ := store.GetJitGrantByID(context.Background(), testAccountID, "g-past")
	if pastGrant.Status != types.GrantStatusExpired {
		t.Errorf("overdue active grant: status = %q, want expired", pastGrant.Status)
	}

	futureGrant, _ := store.GetJitGrantByID(context.Background(), testAccountID, "g-future")
	if futureGrant.Status != types.GrantStatusActive {
		t.Errorf("future active grant: status = %q, want active (untouched)", futureGrant.Status)
	}
}

// ---------------------------------------------------------------------------
// SweepOnce: pending grant auto-deny
// ---------------------------------------------------------------------------

func TestSweepOnce_AutoDeniesStalePendingRequest(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	_ = seedGrantPolicy(t, store)

	// Pending grant whose TTL expired 10 minutes ago.
	seedPendingGrant(t, store, "p-past", "pol-1", "u1", pastTime(10*time.Minute))
	// Pending grant still within TTL.
	seedPendingGrant(t, store, "p-future", "pol-1", "u2", futureTime(10*time.Minute))

	if err := m.SweepOnce(context.Background(), fixedNow); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}

	pastPending, _ := store.GetJitGrantByID(context.Background(), testAccountID, "p-past")
	if pastPending.Status != types.GrantStatusDenied {
		t.Errorf("stale pending grant: status = %q, want denied", pastPending.Status)
	}

	futurePending, _ := store.GetJitGrantByID(context.Background(), testAccountID, "p-future")
	if futurePending.Status != types.GrantStatusPending {
		t.Errorf("fresh pending grant: status = %q, want pending (untouched)", futurePending.Status)
	}
}

// ---------------------------------------------------------------------------
// SweepOnce: resilience — one grant's error must not stop the sweep
// ---------------------------------------------------------------------------

// errorOnceAccount wraps fakeAccount and returns applyErr only for the first
// ApplyJitAutoGroup call, then succeeds for all subsequent calls.
type errorOnceAccount struct {
	*fakeAccount
	calls int
}

func (e *errorOnceAccount) ApplyJitAutoGroup(ctx context.Context, accountID, userID, groupID string, add bool) error {
	e.calls++
	if e.calls == 1 {
		return errors.New("transient failure on first grant")
	}
	return e.fakeAccount.ApplyJitAutoGroup(ctx, accountID, userID, groupID, add)
}

func TestSweepOnce_OneExpireErrorDoesNotStopOthers(t *testing.T) {
	store := newFakeStore()
	prov := newFakeProvisioner()
	events := &fakeEvents{}
	errAccount := &errorOnceAccount{fakeAccount: newFakeAccount()}

	m := jit.NewManager(store, prov, events, errAccount, nil, jit.DefaultMarker, 1440)
	_ = seedGrantPolicy(t, store)

	// Two overdue active grants. The first Expire will fail (membership apply
	// fails), the second must still be expired.
	seedActiveGrant(t, store, "g1", "pol-1", "u1", pastTime(5*time.Minute))
	seedActiveGrant(t, store, "g2", "pol-1", "u2", pastTime(5*time.Minute))

	// SweepOnce must return nil (resilient); individual errors are logged.
	if err := m.SweepOnce(context.Background(), fixedNow); err != nil {
		t.Fatalf("SweepOnce must not return an error even when a grant fails: %v", err)
	}

	// One grant should be expired (the second one, whose membership apply succeeds).
	expiredCount := 0
	for _, g := range store.allGrants() {
		if g.Status == types.GrantStatusExpired {
			expiredCount++
		}
	}
	if expiredCount < 1 {
		t.Error("expected at least one grant to be expired despite the first grant's error")
	}
}

// ---------------------------------------------------------------------------
// SweepOnce: failed grant retry
// ---------------------------------------------------------------------------

func TestSweepOnce_RetriesFailedGrants(t *testing.T) {
	m, store, account, _ := newGrantTestManager(t)
	_ = seedGrantPolicy(t, store)

	// Seed a failed grant (NetBird was down at approval time).
	seedFailedGrant(t, store, "f1", "pol-1", "u1")

	// NetBird is now up; RetryFailed should reactivate.
	account.applyErr = nil

	if err := m.SweepOnce(context.Background(), fixedNow); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}

	got, _ := store.GetJitGrantByID(context.Background(), testAccountID, "f1")
	if got.Status != types.GrantStatusActive {
		t.Errorf("failed grant after retry: status = %q, want active", got.Status)
	}
}

// ---------------------------------------------------------------------------
// SweepOnce: mixed — all three actions in one sweep
// ---------------------------------------------------------------------------

func TestSweepOnce_MixedActionsInOneSweep(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	_ = seedGrantPolicy(t, store)

	seedActiveGrant(t, store, "active-due", "pol-1", "u1", pastTime(time.Minute))
	seedActiveGrant(t, store, "active-ok", "pol-1", "u2", futureTime(time.Hour))
	seedPendingGrant(t, store, "pending-due", "pol-1", "u3", pastTime(time.Minute))
	seedPendingGrant(t, store, "pending-ok", "pol-1", "u4", futureTime(time.Hour))
	seedFailedGrant(t, store, "failed-one", "pol-1", "u5")

	if err := m.SweepOnce(context.Background(), fixedNow); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}

	check := func(id string, want types.GrantStatus) {
		t.Helper()
		g, _ := store.GetJitGrantByID(context.Background(), testAccountID, id)
		if g.Status != want {
			t.Errorf("grant %s: status = %q, want %q", id, g.Status, want)
		}
	}
	check("active-due", types.GrantStatusExpired)
	check("active-ok", types.GrantStatusActive)
	check("pending-due", types.GrantStatusDenied)
	check("pending-ok", types.GrantStatusPending)
	check("failed-one", types.GrantStatusActive) // retried successfully
}

// ---------------------------------------------------------------------------
// SweepOnce: empty store — no crash, no false removals
// ---------------------------------------------------------------------------

func TestSweepOnce_EmptyStoreIsNoOp(t *testing.T) {
	m, _, _, _ := newGrantTestManager(t)
	if err := m.SweepOnce(context.Background(), fixedNow); err != nil {
		t.Fatalf("SweepOnce on empty store: %v", err)
	}
}

// ---------------------------------------------------------------------------
// StartSweeper / Stop — basic loop liveness
// ---------------------------------------------------------------------------

func TestStartSweeper_RunsAndStops(t *testing.T) {
	m, store, _, _ := newGrantTestManager(t)
	_ = seedGrantPolicy(t, store)
	seedActiveGrant(t, store, "sweep-g", "pol-1", "u1", pastTime(time.Minute))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a very short interval so the sweep fires quickly in the test.
	m.StartSweeper(ctx, 20*time.Millisecond)

	// Give the sweeper time to fire at least once.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		g, _ := store.GetJitGrantByID(context.Background(), testAccountID, "sweep-g")
		if g.Status == types.GrantStatusExpired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	g, _ := store.GetJitGrantByID(context.Background(), testAccountID, "sweep-g")
	if g.Status != types.GrantStatusExpired {
		t.Error("sweeper did not expire the overdue grant within 2 seconds")
	}

	// Stop must not block.
	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("Stop() blocked for >1s")
	}
}
