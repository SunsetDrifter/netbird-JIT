package server

import (
	"time"

	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/jit/jitprovisioner"
)

const (
	// jitDefaultPendingTTLMinutes is applied to a created JIT policy when the
	// caller does not specify a pending TTL. It mirrors the TypeScript sidecar's
	// JIT_PENDING_TTL_MINUTES default (1440 = 24h).
	//
	// TODO(jit): expose this and jitSweepInterval as management config knobs
	// (e.g. under Config.JIT) once the feature graduates from its default wiring.
	jitDefaultPendingTTLMinutes = 1440

	// jitSweepInterval is how often the background sweeper expires due grants,
	// auto-denies stale pending requests, and retries failed grants. 30s keeps
	// expiry latency low without meaningful load (each tick is a few indexed
	// queries). See the TODO above re: making this configurable.
	jitSweepInterval = 30 * time.Second
)

// JitManager constructs (once) the JIT subsystem manager and wires it to the
// real account + network-resources managers and the store.
//
// Interface satisfaction:
//   - the store (store.Store)        -> jit.Store      (the persistence ops)
//   - the provisioner Adapter        -> jit's provisioner (group/policy/resource ops)
//   - the account.Manager            -> jit.EventEmitter (StoreEvent) AND
//     jit's accountOps (ApplyJitAutoGroup + GetAccountSettings)
//   - nil grants                     -> the manager self-wires as its own
//     grantCanceller (TerminateGrantsForPolicy), per Task 7.
//
// The sweeper is NOT started here (construction must stay side-effect free for
// the lazy container); Start() calls StartSweeper and Stop() calls Stop.
func (s *BaseServer) JitManager() *jit.Manager {
	return Create(s, func() *jit.Manager {
		prov := jitprovisioner.New(s.AccountManager(), s.ResourcesManager())
		return jit.NewManager(
			s.Store(),          // jit.Store
			prov,               // provisioner
			s.AccountManager(), // jit.EventEmitter (StoreEvent)
			s.AccountManager(), // jit accountOps (ApplyJitAutoGroup + GetAccountSettings)
			nil,                // grantCanceller: self-wire (m.grants = m)
			jit.DefaultMarker,  // marker prefix for JIT-owned objects
			jitDefaultPendingTTLMinutes,
		)
	})
}
