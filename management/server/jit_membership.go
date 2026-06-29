package server

import (
	"context"
	"fmt"
	"slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ApplyJitAutoGroup adds or removes a single JIT backing group from a user's
// auto_groups and, when group propagation is enabled, mirrors that change onto
// the user's peers — exactly as processUserUpdate does for a normal user save.
//
// It is system-authorized: unlike SaveOrAddUsers it does NOT run the
// modules.Users permission gate. JIT authorizes at the grant layer and the
// scheduler acts as the system, so this method must be reachable without an
// initiator. The grant service and scheduler are the only callers.
//
// Invariants:
//   - groupID MUST resolve to an api-issued group (types.GroupIssuedAPI). If it
//     is a jwt or integration group the method errors and mutates NOTHING — JIT
//     never touches IdP/JWT group membership.
//   - The change is idempotent: adding an already-present group, removing an
//     absent one, or removing from a user that no longer exists are all no-op
//     successes with no peer churn and no network-serial bump. Adding to a
//     non-existent user is an error.
//
// Locking follows the same approach as the comparable membership mutations in
// this package (GroupAddPeer/GroupDeletePeer/UpdateGroup, and SaveOrAddUsers):
// no account-manager-level lock is taken here. All reads and writes happen
// inside a single ExecuteInTransaction for atomicity, and the post-commit
// UpdateAccountPeers runs outside it. As with SaveOrAddUsers, it is the caller's
// responsibility to provide any higher-level serialization it needs.
func (am *DefaultAccountManager) ApplyJitAutoGroup(ctx context.Context, accountID, userID, groupID string, add bool) error {
	// propagated is set only when the change actually altered peer group
	// membership (propagation on AND the user has peers). It gates the
	// post-commit network-map push so idempotent / peerless changes stay quiet.
	var propagated bool

	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		user, err := transaction.GetUserByUserID(ctx, store.LockingStrengthUpdate, userID)
		if err != nil {
			// Removing membership for a user that is already gone is the desired
			// end state — treat as a no-op success. Adding requires the user.
			if !add && isNotFound(err) {
				return nil
			}
			return err
		}

		if user.AccountID != accountID {
			return status.Errorf(status.InvalidArgument, "user %s does not belong to account %s", userID, accountID)
		}

		// Hard invariant: only ever mutate the single api-issued backing group.
		group, err := transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
		if err != nil {
			return err
		}
		if group.Issued != types.GroupIssuedAPI {
			return status.Errorf(status.InvalidArgument,
				"refusing to modify membership of non-api group %s (issued=%q)", groupID, group.Issued)
		}

		newAutoGroups, changed := applyAutoGroup(user.AutoGroups, groupID, add)
		if !changed {
			return nil // idempotent: already in desired state
		}

		updatedUser := user.Copy()
		updatedUser.AutoGroups = newAutoGroups
		if err := transaction.SaveUser(ctx, updatedUser); err != nil {
			return fmt.Errorf("failed to save user %s: %w", userID, err)
		}

		settings, err := transaction.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return err
		}
		if !settings.GroupsPropagationEnabled {
			return nil
		}

		userPeers, err := transaction.GetUserPeers(ctx, store.LockingStrengthNone, accountID, userID)
		if err != nil {
			return err
		}
		if len(userPeers) == 0 {
			return nil
		}

		if err := propagateToPeers(ctx, transaction, accountID, groupID, userPeers, add); err != nil {
			return err
		}

		// Mirror processUserUpdate: reconcile IPv6 for the single changed group.
		if err := am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{groupID}); err != nil {
			return fmt.Errorf("reconcile IPv6 for group %s: %w", groupID, err)
		}

		propagated = true
		return nil
	})
	if err != nil {
		return err
	}

	// Mirror the SaveOrAddUsers post-commit path: only when peers actually
	// changed group membership do we bump the serial and push a network map.
	if propagated {
		if err := am.Store.IncrementNetworkSerial(ctx, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}
		am.UpdateAccountPeers(ctx, accountID, types.UpdateReason{
			Resource:  types.UpdateResourceUser,
			Operation: types.UpdateOperationUpdate,
		})
	}

	return nil
}

// applyAutoGroup returns the auto_groups slice with groupID added (when add) or
// removed (when !add), and whether it differs from the input. The input slice is
// never mutated.
func applyAutoGroup(autoGroups []string, groupID string, add bool) ([]string, bool) {
	present := slices.Contains(autoGroups, groupID)
	if add {
		if present {
			return autoGroups, false
		}
		next := make([]string, len(autoGroups), len(autoGroups)+1)
		copy(next, autoGroups)
		return append(next, groupID), true
	}

	if !present {
		return autoGroups, false
	}
	next := make([]string, 0, len(autoGroups))
	for _, g := range autoGroups {
		if g != groupID {
			next = append(next, g)
		}
	}
	return next, true
}

// propagateToPeers adds or removes the group from each of the user's peers,
// matching the GroupsPropagationEnabled loop in processUserUpdate.
func propagateToPeers(ctx context.Context, transaction store.Store, accountID, groupID string, peers []*nbpeer.Peer, add bool) error {
	for _, peer := range peers {
		if add {
			if err := transaction.AddPeerToGroup(ctx, accountID, peer.ID, groupID); err != nil {
				return fmt.Errorf("failed to add peer %s to group %s: %w", peer.ID, groupID, err)
			}
			continue
		}
		if err := transaction.RemovePeerFromGroup(ctx, peer.ID, groupID); err != nil {
			return fmt.Errorf("failed to remove peer %s from group %s: %w", peer.ID, groupID, err)
		}
	}
	return nil
}

// isNotFound reports whether err is a NetBird NotFound status error.
func isNotFound(err error) bool {
	sErr, ok := status.FromError(err)
	return ok && sErr.Type() == status.NotFound
}
