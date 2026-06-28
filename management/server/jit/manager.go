package jit

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/types"
)

// Store is the set of persistence operations the JIT package needs. The real
// store.Store satisfies it; unit tests satisfy it with an in-memory fake. The
// signatures are copied verbatim from store.Store so the concrete store is a
// drop-in (a compile-time assertion in the store package guarantees this).
//
// Keeping the dependency as a narrow interface (rather than importing the store
// package directly) avoids an import cycle and lets every JIT service be tested
// without a database.
type Store interface {
	// JIT policies.
	SaveJitPolicy(ctx context.Context, policy *types.JitPolicy) error
	GetJitPolicyByID(ctx context.Context, accountID, policyID string) (*types.JitPolicy, error)
	ListJitPolicies(ctx context.Context, accountID string) ([]*types.JitPolicy, error)
	DeleteJitPolicy(ctx context.Context, accountID, policyID string) error

	// JIT grants.
	CreateJitGrant(ctx context.Context, grant *types.JitGrant) error
	GetJitGrantByID(ctx context.Context, accountID, grantID string) (*types.JitGrant, error)
	ListJitGrantsByRequester(ctx context.Context, accountID, requesterUserID string) ([]*types.JitGrant, error)
	ListJitGrantsByAccount(ctx context.Context, accountID string, status types.GrantStatus) ([]*types.JitGrant, error)
	GetActiveJitGrantFor(ctx context.Context, accountID, requesterUserID, policyID string) (*types.JitGrant, error)
	ListActiveJitGrantsExpiringBefore(ctx context.Context, threshold time.Time) ([]*types.JitGrant, error)
	ListPendingJitGrantsExpiringBefore(ctx context.Context, threshold time.Time) ([]*types.JitGrant, error)
	// ListFailedJitGrants returns all failed grants across all accounts for
	// the global retry sweep.
	ListFailedJitGrants(ctx context.Context) ([]*types.JitGrant, error)
	ActiveGrantUserIDsForPolicy(ctx context.Context, accountID, policyID string) ([]string, error)
	TransitionJitGrantStatus(ctx context.Context, grantID string, from, to types.GrantStatus, patch types.JitGrantPatch) (*types.JitGrant, bool, error)
}

// EventEmitter records activity events for the audit log. account.Manager
// satisfies it via its StoreEvent method.
type EventEmitter interface {
	StoreEvent(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
}

// grantCanceller voids every grant (active + pending) attached to a JIT policy
// and removes the corresponding backing-group memberships. It is the
// delete-cascade dependency: DeletePolicy calls it before tearing down the
// backing objects so no grant is left pointing at a deleted policy.
//
// Task 7 (the grant service) implements this; the manager only holds the
// interface so the two packages stay decoupled.
type grantCanceller interface {
	TerminateGrantsForPolicy(ctx context.Context, accountID, policyID, reason string) error
}

// Manager is the JIT package hub. It owns CRUD over JIT policies (this task)
// and is the struct grant operations (Task 7) and the HTTP handlers (Task 9)
// hang their methods off of.
//
// Every operation is account-scoped: callers pass an accountID that is threaded
// through to the store and the provisioner, so a caller can never reach another
// account's policies.
type Manager struct {
	store   Store
	prov    provisioner
	events  EventEmitter
	account accountOps
	grants  grantCanceller

	// marker prefixes every JIT-owned NetBird object name so the hidden-object
	// filter can identify and hide them.
	marker string

	// defaultPendingTTL is applied to a created policy when the caller does not
	// specify one (mirrors the sidecar's JIT_PENDING_TTL_MINUTES default).
	defaultPendingTTL int

	// allowSelfApproval, when true, lets an approver approve their own request.
	// Off by default (mirrors the sidecar's allowSelfApproval default of false);
	// wired from config in Task 9.
	allowSelfApproval bool

	// sweeper holds the background sweep-loop control state.
	sweeper sweeper
}

// NewManager wires the JIT manager.
//
// account provides the system-authorized membership primitive + settings read
// the grant service needs (Task 9 passes account.Manager).
//
// grants is the delete-cascade dependency DeletePolicy calls. The Manager now
// implements grantCanceller itself (TerminateGrantsForPolicy), so passing nil
// self-wires the manager as its own canceller — the production path. Tests may
// inject a fake grantCanceller to assert the cascade in isolation.
func NewManager(
	store Store,
	prov provisioner,
	events EventEmitter,
	account accountOps,
	grants grantCanceller,
	marker string,
	defaultPendingTTL int,
) *Manager {
	m := &Manager{
		store:             store,
		prov:              prov,
		events:            events,
		account:           account,
		grants:            grants,
		marker:            marker,
		defaultPendingTTL: defaultPendingTTL,
	}
	if m.grants == nil {
		m.grants = m // self-wire: the manager is its own grant canceller
	}
	return m
}
