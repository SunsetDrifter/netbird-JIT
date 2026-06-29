// Package jit implements the grant lifecycle state machine for Just-in-Time access.
// Every status change on a JitGrant is funnelled through Transition, which validates
// the edge against the LEGAL table and performs an atomic compare-and-set via the store.
package jit

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ErrTransitionConflict is returned by Transition when the compare-and-set fails
// because a concurrent caller already moved the grant out of its expected status
// (ok==false from the store). Callers may treat this as a 409 or a benign skip.
var ErrTransitionConflict = errors.New("jit: grant transition conflict: concurrent status change")

// legal is the authoritative set of permitted status edges for a JitGrant.
// It mirrors the LEGAL table in grantLifecycle.ts exactly.
// The string value is the audit-action label for the edge.
//
// Terminal statuses (expired, denied, revoked, cancelled, superseded) have no
// outgoing edges and therefore no entries as map keys.
//
// failed → failed is a deliberate self-edge: a retry that fails again re-stamps
// lastError and re-audits "grant.fail", matching the pre-existing retry behaviour.
var legal = map[types.GrantStatus]map[types.GrantStatus]string{
	types.GrantStatusPending: {
		types.GrantStatusApproved:  "grant.approve",
		types.GrantStatusDenied:    "grant.deny",
		types.GrantStatusCancelled: "grant.cancel",
	},
	types.GrantStatusApproved: {
		types.GrantStatusActive:    "grant.activate",
		types.GrantStatusFailed:    "grant.fail",
		types.GrantStatusCancelled: "grant.cancel",
	},
	types.GrantStatusActive: {
		types.GrantStatusExpired:    "grant.expire",
		types.GrantStatusRevoked:    "grant.revoke",
		types.GrantStatusSuperseded: "grant.supersede",
	},
	types.GrantStatusFailed: {
		types.GrantStatusActive:  "grant.activate",
		types.GrantStatusRevoked: "grant.revoke",
		types.GrantStatusFailed:  "grant.fail",
	},
}

// grantTransitioner is the minimal store interface consumed by this package.
// store.Store satisfies it; a fake can satisfy it in tests.
type grantTransitioner interface {
	TransitionJitGrantStatus(ctx context.Context, grantID string, from, to types.GrantStatus, patch types.JitGrantPatch) (*types.JitGrant, bool, error)
}

// IsLegalTransition reports whether the from→to edge exists in the LEGAL table.
func IsLegalTransition(from, to types.GrantStatus) bool {
	_, ok := legal[from][to]
	return ok
}

// ActionForEdge returns the audit-action label for a from→to edge and true,
// or ("", false) if the edge is illegal.
// This is a pure function; it does not touch any store or external system.
func ActionForEdge(from, to types.GrantStatus) (string, bool) {
	action, ok := legal[from][to]
	return action, ok
}

// Transition moves grant to status to via an atomic compare-and-set.
//
// Steps:
//  1. Validates from→to against the LEGAL table; returns a PreconditionFailed
//     error if the edge is illegal.
//  2. Calls t.TransitionJitGrantStatus with the current grant status as the
//     expected-from value.
//  3. If the store returns ok==false (lost race), returns ErrTransitionConflict.
//  4. On success, returns the updated grant.
//
// Callers receive the derived audit-action label via ActionForEdge; they are
// responsible for emitting activity events.
func Transition(
	ctx context.Context,
	t grantTransitioner,
	grant *types.JitGrant,
	to types.GrantStatus,
	patch types.JitGrantPatch,
) (*types.JitGrant, error) {
	from := grant.Status

	if !IsLegalTransition(from, to) {
		return nil, status.Errorf(
			status.PreconditionFailed,
			"illegal grant transition: %s → %s",
			from, to,
		)
	}

	updated, ok, err := t.TransitionJitGrantStatus(ctx, grant.ID, from, to, patch)
	if err != nil {
		return nil, fmt.Errorf("jit: transition %s→%s for grant %s: %w", from, to, grant.ID, err)
	}
	if !ok {
		return nil, ErrTransitionConflict
	}

	return updated, nil
}
