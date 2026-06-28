package jit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// SweepOnce runs one expiry sweep as of the given `now`. It is the core of the
// background sweeper and is also callable directly (e.g. from tests with a
// controlled clock or after a state change that may make a grant immediately due).
//
// Three passes, all resilient:
//  1. Expire active grants whose ExpiresAt ≤ now.
//  2. Auto-deny pending grants whose PendingExpiresAt ≤ now.
//  3. Retry every failed grant (membership apply may now succeed).
//
// Resilient means: one grant's error is logged and skipped; the sweep continues
// and returns nil so the caller does not treat a partial failure as a fatal one.
// A failed grant stays in its current state and is re-attempted next sweep.
func (m *Manager) SweepOnce(ctx context.Context, now time.Time) error {
	m.sweepExpireActive(ctx, now)
	m.sweepAutoDenyPending(ctx, now)
	m.sweepRetryFailed(ctx)
	return nil
}

// sweepExpireActive lists active grants due before `now` and calls Expire on
// each. Errors are logged; the loop continues regardless.
func (m *Manager) sweepExpireActive(ctx context.Context, now time.Time) {
	grants, err := m.store.ListActiveJitGrantsExpiringBefore(ctx, now)
	if err != nil {
		log.WithContext(ctx).Errorf("jit sweeper: list expiring active grants: %v", err)
		return
	}
	for _, g := range grants {
		if _, err := m.Expire(ctx, g); err != nil {
			log.WithContext(ctx).Errorf("jit sweeper: expire grant %s (account %s): %v", g.ID, g.AccountID, err)
			// continue — other grants must still be processed
		}
	}
}

// sweepAutoDenyPending lists pending grants past their TTL and auto-denies each.
func (m *Manager) sweepAutoDenyPending(ctx context.Context, now time.Time) {
	grants, err := m.store.ListPendingJitGrantsExpiringBefore(ctx, now)
	if err != nil {
		log.WithContext(ctx).Errorf("jit sweeper: list stale pending grants: %v", err)
		return
	}
	for _, g := range grants {
		if _, err := m.AutoDenyPending(ctx, g); err != nil {
			log.WithContext(ctx).Errorf("jit sweeper: auto-deny pending grant %s (account %s): %v", g.ID, g.AccountID, err)
		}
	}
}

// sweepRetryFailed lists all failed grants and re-attempts activation for each.
// A failed grant stays failed if the membership apply still errors; it will be
// retried again next sweep.
func (m *Manager) sweepRetryFailed(ctx context.Context) {
	grants, err := m.store.ListFailedJitGrants(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("jit sweeper: list failed grants: %v", err)
		return
	}
	for _, g := range grants {
		if err := m.RetryFailed(ctx, g); err != nil {
			log.WithContext(ctx).Errorf("jit sweeper: retry failed grant %s (account %s): %v", g.ID, g.AccountID, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Background sweeper loop
// ---------------------------------------------------------------------------

// sweeper holds the goroutine control state for the background sweep loop.
// It is embedded in Manager and zero-value-safe before StartSweeper is called.
type sweeper struct {
	mu      sync.Mutex
	stopCh  chan struct{}
	stopped bool

	// running is an atomic flag used as a re-entrancy guard: if a sweep tick
	// fires while the previous sweep is still executing, the new tick is skipped.
	running atomic.Bool
}

// StartSweeper launches a background goroutine that calls SweepOnce every
// `interval`. A re-entrancy guard (atomic bool) skips a tick if the previous
// sweep has not yet finished, so slow sweeps do not pile up. The loop exits
// when Stop is called or ctx is cancelled.
//
// Callers must call Stop (or cancel ctx) to release the goroutine. StartSweeper
// is idempotent: a second call while the sweeper is running is a no-op.
func (m *Manager) StartSweeper(ctx context.Context, interval time.Duration) {
	m.sweeper.mu.Lock()
	defer m.sweeper.mu.Unlock()

	if m.sweeper.stopCh != nil && !m.sweeper.stopped {
		return // already running
	}
	m.sweeper.stopCh = make(chan struct{})
	m.sweeper.stopped = false

	stopCh := m.sweeper.stopCh // capture for the goroutine
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if !m.sweeper.running.CompareAndSwap(false, true) {
					log.WithContext(ctx).Debugf("jit sweeper: previous sweep still running, skipping tick")
					continue
				}
				go func() {
					defer m.sweeper.running.Store(false)
					if err := m.SweepOnce(ctx, time.Now().UTC()); err != nil {
						log.WithContext(ctx).Errorf("jit sweeper: sweep error: %v", err)
					}
				}()
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop signals the sweeper goroutine to exit. It returns immediately after
// signalling; it does not wait for any in-progress sweep to complete (in-flight
// grant operations are concurrency-safe). Safe to call multiple times.
func (m *Manager) Stop() {
	m.sweeper.mu.Lock()
	defer m.sweeper.mu.Unlock()

	if m.sweeper.stopCh != nil && !m.sweeper.stopped {
		m.sweeper.stopped = true
		close(m.sweeper.stopCh)
	}
}
