package server

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// jitMembershipFixture builds a sqlite-backed account with one owner user, a
// registered peer owned by that user, and an API-issued backing group. It
// returns the manager, account ID, owner user ID, the backing group ID, and the
// registered peer ID. Group propagation is left at its default (enabled);
// callers that need it off disable it via the store.
func jitMembershipFixture(t *testing.T) (am *DefaultAccountManager, accountID, userID, groupID, peerID string) {
	t.Helper()

	am, _, err := createManager(t)
	require.NoError(t, err)

	ctx := context.Background()
	userID = groupAdminUserID

	account, err := createAccount(am, "jit-membership-test", userID, "jit.example.com")
	require.NoError(t, err)
	accountID = account.Id

	groupID = "jit-backing-grp"
	require.NoError(t, am.CreateGroup(ctx, accountID, userID, &types.Group{
		ID:     groupID,
		Name:   "JIT Backing Group",
		Issued: types.GroupIssuedAPI,
		Peers:  []string{},
	}))

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	// Register the peer under the user (interactive login flow), not a setup key:
	// GetUserPeers only returns peers with a non-empty user_id, and JIT propagation
	// (like processUserUpdate) acts on the user's own peers.
	peer, _, _, _, err := am.AddPeer(ctx, "", "", userID, &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "jit-test-host"},
	}, false)
	require.NoError(t, err)
	peerID = peer.ID

	return am, accountID, userID, groupID, peerID
}

func userAutoGroups(t *testing.T, am *DefaultAccountManager, accountID, userID string) []string {
	t.Helper()
	user, err := am.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, userID)
	require.NoError(t, err)
	require.Equal(t, accountID, user.AccountID)
	return user.AutoGroups
}

func groupHasPeer(t *testing.T, am *DefaultAccountManager, accountID, groupID, peerID string) bool {
	t.Helper()
	group, err := am.Store.GetGroupByID(context.Background(), store.LockingStrengthNone, accountID, groupID)
	require.NoError(t, err)
	return slices.Contains(group.Peers, peerID)
}

func TestApplyJitAutoGroup_AddPropagatesToPeer(t *testing.T) {
	am, accountID, userID, groupID, peerID := jitMembershipFixture(t)
	ctx := context.Background()

	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, userID, groupID, true))

	assert.Contains(t, userAutoGroups(t, am, accountID, userID), groupID,
		"backing group should be present in AutoGroups after add")
	assert.True(t, groupHasPeer(t, am, accountID, groupID, peerID),
		"with propagation on, the user's peer should be a member of the backing group")
}

func TestApplyJitAutoGroup_RemoveReversesAdd(t *testing.T) {
	am, accountID, userID, groupID, peerID := jitMembershipFixture(t)
	ctx := context.Background()

	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, userID, groupID, true))
	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, userID, groupID, false))

	assert.NotContains(t, userAutoGroups(t, am, accountID, userID), groupID,
		"backing group should be gone from AutoGroups after remove")
	assert.False(t, groupHasPeer(t, am, accountID, groupID, peerID),
		"the user's peer should no longer be a member of the backing group after remove")
}

func TestApplyJitAutoGroup_PropagationOffSkipsPeerMembership(t *testing.T) {
	am, accountID, userID, groupID, peerID := jitMembershipFixture(t)
	ctx := context.Background()

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	settings.GroupsPropagationEnabled = false
	require.NoError(t, am.Store.SaveAccountSettings(ctx, accountID, settings))

	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, userID, groupID, true))

	assert.Contains(t, userAutoGroups(t, am, accountID, userID), groupID,
		"AutoGroups should change even with propagation off")
	assert.False(t, groupHasPeer(t, am, accountID, groupID, peerID),
		"with propagation off, the peer must NOT be added to the backing group")
}

func TestApplyJitAutoGroup_NonAPIGroupErrorsAndMutatesNothing(t *testing.T) {
	am, accountID, userID, _, _ := jitMembershipFixture(t)
	ctx := context.Background()

	jwtGroupID := "jit-jwt-grp"
	require.NoError(t, am.CreateGroup(ctx, accountID, userID, &types.Group{
		ID:     jwtGroupID,
		Name:   "JWT Group",
		Issued: types.GroupIssuedJWT,
		Peers:  []string{},
	}))

	before := userAutoGroups(t, am, accountID, userID)

	err := am.ApplyJitAutoGroup(ctx, accountID, userID, jwtGroupID, true)
	require.Error(t, err, "targeting a non-api group must error")

	assert.Equal(t, before, userAutoGroups(t, am, accountID, userID),
		"AutoGroups must be unchanged when the target group is not api-issued")
}

func TestApplyJitAutoGroup_AddWhenPresentIsNoOp(t *testing.T) {
	am, accountID, userID, groupID, _ := jitMembershipFixture(t)
	ctx := context.Background()

	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, userID, groupID, true))
	first := userAutoGroups(t, am, accountID, userID)

	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, userID, groupID, true),
		"adding an already-present group must be a no-op success")

	assert.Equal(t, first, userAutoGroups(t, am, accountID, userID),
		"AutoGroups must be unchanged on a redundant add")
}

func TestApplyJitAutoGroup_RemoveWhenAbsentIsNoOp(t *testing.T) {
	am, accountID, userID, groupID, _ := jitMembershipFixture(t)
	ctx := context.Background()

	before := userAutoGroups(t, am, accountID, userID)

	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, userID, groupID, false),
		"removing an absent group must be a no-op success")

	assert.Equal(t, before, userAutoGroups(t, am, accountID, userID),
		"AutoGroups must be unchanged on a redundant remove")
}

func TestApplyJitAutoGroup_AccountMismatchErrors(t *testing.T) {
	am, _, userID, groupID, _ := jitMembershipFixture(t)
	ctx := context.Background()

	err := am.ApplyJitAutoGroup(ctx, "some-other-account", userID, groupID, true)
	require.Error(t, err, "a userID that does not belong to accountID must error")
}

func TestApplyJitAutoGroup_UserNotFoundOnRemoveIsNoOp(t *testing.T) {
	am, accountID, _, groupID, _ := jitMembershipFixture(t)
	ctx := context.Background()

	require.NoError(t, am.ApplyJitAutoGroup(ctx, accountID, "ghost-user", groupID, false),
		"removing from a non-existent user must be a no-op success (grant/user already gone)")
}

func TestApplyJitAutoGroup_UserNotFoundOnAddErrors(t *testing.T) {
	am, accountID, _, groupID, _ := jitMembershipFixture(t)
	ctx := context.Background()

	err := am.ApplyJitAutoGroup(ctx, accountID, "ghost-user", groupID, true)
	require.Error(t, err, "adding to a non-existent user must error")
}
