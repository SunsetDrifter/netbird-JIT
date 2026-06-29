package jit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/types"
)

// fakeTransitioner is a test double for the grantTransitioner interface.
// It records whether it was called and controls the returned values.
type fakeTransitioner struct {
	called   bool
	returnOK bool
	returnErr error
	returnGrant *types.JitGrant
}

func (f *fakeTransitioner) TransitionJitGrantStatus(
	_ context.Context,
	grantID string,
	from, to types.GrantStatus,
	_ types.JitGrantPatch,
) (*types.JitGrant, bool, error) {
	f.called = true
	if f.returnErr != nil {
		return nil, false, f.returnErr
	}
	if !f.returnOK {
		return nil, false, nil
	}
	g := &types.JitGrant{ID: grantID, Status: to}
	if f.returnGrant != nil {
		g = f.returnGrant
	}
	return g, true, nil
}

// helper returns a grant in the given status.
func grantWith(id string, s types.GrantStatus) *types.JitGrant {
	return &types.JitGrant{ID: id, Status: s}
}

// -----------------------------------------------------------------------
// IsLegalTransition tests
// -----------------------------------------------------------------------

func TestIsLegalTransition_LegalEdges(t *testing.T) {
	legalEdges := [][2]types.GrantStatus{
		{types.GrantStatusPending, types.GrantStatusApproved},
		{types.GrantStatusPending, types.GrantStatusDenied},
		{types.GrantStatusPending, types.GrantStatusCancelled},
		{types.GrantStatusApproved, types.GrantStatusActive},
		{types.GrantStatusApproved, types.GrantStatusFailed},
		{types.GrantStatusApproved, types.GrantStatusCancelled},
		{types.GrantStatusActive, types.GrantStatusExpired},
		{types.GrantStatusActive, types.GrantStatusRevoked},
		{types.GrantStatusActive, types.GrantStatusSuperseded},
		{types.GrantStatusFailed, types.GrantStatusActive},
		{types.GrantStatusFailed, types.GrantStatusRevoked},
		{types.GrantStatusFailed, types.GrantStatusFailed}, // self-edge
	}

	for _, e := range legalEdges {
		from, to := e[0], e[1]
		if !jit.IsLegalTransition(from, to) {
			t.Errorf("expected legal: %s → %s", from, to)
		}
	}
}

func TestIsLegalTransition_IllegalEdges(t *testing.T) {
	illegalEdges := [][2]types.GrantStatus{
		// Terminal statuses have no outgoing edges.
		{types.GrantStatusExpired, types.GrantStatusActive},
		{types.GrantStatusDenied, types.GrantStatusPending},
		{types.GrantStatusRevoked, types.GrantStatusActive},
		{types.GrantStatusCancelled, types.GrantStatusPending},
		{types.GrantStatusSuperseded, types.GrantStatusActive},
		// Cross-status shortcuts that don't exist.
		{types.GrantStatusPending, types.GrantStatusActive},
		{types.GrantStatusPending, types.GrantStatusExpired},
		{types.GrantStatusApproved, types.GrantStatusExpired},
		{types.GrantStatusActive, types.GrantStatusApproved},
		{types.GrantStatusFailed, types.GrantStatusExpired},
	}

	for _, e := range illegalEdges {
		from, to := e[0], e[1]
		if jit.IsLegalTransition(from, to) {
			t.Errorf("expected illegal: %s → %s", from, to)
		}
	}
}

// -----------------------------------------------------------------------
// ActionForEdge tests — exact strings ported from grantLifecycle.ts
// -----------------------------------------------------------------------

func TestActionForEdge_LegalEdges(t *testing.T) {
	cases := []struct {
		from, to types.GrantStatus
		want     string
	}{
		{types.GrantStatusPending, types.GrantStatusApproved, "grant.approve"},
		{types.GrantStatusPending, types.GrantStatusDenied, "grant.deny"},
		{types.GrantStatusPending, types.GrantStatusCancelled, "grant.cancel"},
		{types.GrantStatusApproved, types.GrantStatusActive, "grant.activate"},
		{types.GrantStatusApproved, types.GrantStatusFailed, "grant.fail"},
		{types.GrantStatusApproved, types.GrantStatusCancelled, "grant.cancel"},
		{types.GrantStatusActive, types.GrantStatusExpired, "grant.expire"},
		{types.GrantStatusActive, types.GrantStatusRevoked, "grant.revoke"},
		{types.GrantStatusActive, types.GrantStatusSuperseded, "grant.supersede"},
		{types.GrantStatusFailed, types.GrantStatusActive, "grant.activate"},
		{types.GrantStatusFailed, types.GrantStatusRevoked, "grant.revoke"},
		{types.GrantStatusFailed, types.GrantStatusFailed, "grant.fail"},
	}

	for _, c := range cases {
		action, ok := jit.ActionForEdge(c.from, c.to)
		if !ok {
			t.Errorf("ActionForEdge(%s, %s): expected ok=true", c.from, c.to)
			continue
		}
		if action != c.want {
			t.Errorf("ActionForEdge(%s, %s): got %q, want %q", c.from, c.to, action, c.want)
		}
	}
}

func TestActionForEdge_IllegalEdges(t *testing.T) {
	cases := [][2]types.GrantStatus{
		{types.GrantStatusExpired, types.GrantStatusActive},
		{types.GrantStatusPending, types.GrantStatusActive},
		{types.GrantStatusActive, types.GrantStatusApproved},
	}

	for _, c := range cases {
		_, ok := jit.ActionForEdge(c[0], c[1])
		if ok {
			t.Errorf("ActionForEdge(%s, %s): expected ok=false for illegal edge", c[0], c[1])
		}
	}
}

// -----------------------------------------------------------------------
// Transition tests
// -----------------------------------------------------------------------

func TestTransition_LegalEdge_Success(t *testing.T) {
	fake := &fakeTransitioner{returnOK: true}
	grant := grantWith("g1", types.GrantStatusPending)

	updated, err := jit.Transition(context.Background(), fake, grant, types.GrantStatusApproved, types.JitGrantPatch{})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !fake.called {
		t.Fatal("expected TransitionJitGrantStatus to be called")
	}
	if updated == nil {
		t.Fatal("expected non-nil updated grant")
	}
	if updated.Status != types.GrantStatusApproved {
		t.Errorf("expected status %s, got %s", types.GrantStatusApproved, updated.Status)
	}
}

func TestTransition_IllegalEdge_ReturnsError_NeverCallsStore(t *testing.T) {
	illegalEdges := [][2]types.GrantStatus{
		{types.GrantStatusPending, types.GrantStatusActive},
		{types.GrantStatusExpired, types.GrantStatusActive},
		{types.GrantStatusActive, types.GrantStatusApproved},
		{types.GrantStatusDenied, types.GrantStatusPending},
	}

	for _, e := range illegalEdges {
		fake := &fakeTransitioner{}
		grant := grantWith("g1", e[0])

		_, err := jit.Transition(context.Background(), fake, grant, e[1], types.JitGrantPatch{})

		if err == nil {
			t.Errorf("expected error for illegal edge %s → %s", e[0], e[1])
		}
		if fake.called {
			t.Errorf("expected store NOT to be called for illegal edge %s → %s", e[0], e[1])
		}
	}
}

func TestTransition_LostRace_ReturnsErrTransitionConflict(t *testing.T) {
	// Fake returns ok=false (lost compare-and-set race).
	fake := &fakeTransitioner{returnOK: false}
	grant := grantWith("g1", types.GrantStatusPending)

	_, err := jit.Transition(context.Background(), fake, grant, types.GrantStatusApproved, types.JitGrantPatch{})

	if err == nil {
		t.Fatal("expected error on lost race, got nil")
	}
	if !errors.Is(err, jit.ErrTransitionConflict) {
		t.Errorf("expected ErrTransitionConflict, got: %v", err)
	}
	if !fake.called {
		t.Fatal("expected store to be called on a legal edge before detecting lost race")
	}
}

func TestTransition_StoreError_Propagated(t *testing.T) {
	storeErr := errors.New("database down")
	fake := &fakeTransitioner{returnErr: storeErr}
	grant := grantWith("g1", types.GrantStatusApproved)

	_, err := jit.Transition(context.Background(), fake, grant, types.GrantStatusActive, types.JitGrantPatch{})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// The underlying store error should be wrapped/present.
	if !errors.Is(err, storeErr) {
		t.Errorf("expected store error to be wrapped in returned error, got: %v", err)
	}
}

func TestTransition_FailedSelfEdge_Success(t *testing.T) {
	// failed → failed is a deliberate self-edge (retry that fails again).
	fake := &fakeTransitioner{returnOK: true}
	grant := grantWith("g2", types.GrantStatusFailed)

	updated, err := jit.Transition(context.Background(), fake, grant, types.GrantStatusFailed, types.JitGrantPatch{})

	if err != nil {
		t.Fatalf("expected no error on failed→failed, got: %v", err)
	}
	if updated == nil {
		t.Fatal("expected non-nil updated grant")
	}
}

// TestTransition_AllLegalEdges exhaustively checks every legal edge calls the store
// and returns no error.
func TestTransition_AllLegalEdges(t *testing.T) {
	legalEdges := [][2]types.GrantStatus{
		{types.GrantStatusPending, types.GrantStatusApproved},
		{types.GrantStatusPending, types.GrantStatusDenied},
		{types.GrantStatusPending, types.GrantStatusCancelled},
		{types.GrantStatusApproved, types.GrantStatusActive},
		{types.GrantStatusApproved, types.GrantStatusFailed},
		{types.GrantStatusApproved, types.GrantStatusCancelled},
		{types.GrantStatusActive, types.GrantStatusExpired},
		{types.GrantStatusActive, types.GrantStatusRevoked},
		{types.GrantStatusActive, types.GrantStatusSuperseded},
		{types.GrantStatusFailed, types.GrantStatusActive},
		{types.GrantStatusFailed, types.GrantStatusRevoked},
		{types.GrantStatusFailed, types.GrantStatusFailed},
	}

	for _, e := range legalEdges {
		fake := &fakeTransitioner{returnOK: true}
		grant := grantWith("g-edge", e[0])

		updated, err := jit.Transition(context.Background(), fake, grant, e[1], types.JitGrantPatch{})
		if err != nil {
			t.Errorf("edge %s → %s: unexpected error: %v", e[0], e[1], err)
		}
		if !fake.called {
			t.Errorf("edge %s → %s: store not called", e[0], e[1])
		}
		if updated == nil {
			t.Errorf("edge %s → %s: expected non-nil updated grant", e[0], e[1])
		}
	}
}
