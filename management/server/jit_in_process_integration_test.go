package server

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/jit/jitprovisioner"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestJitInProcessEndToEnd is the crown-jewel integration test for the JIT
// in-core wiring (Task 9b). It uses the REAL DefaultAccountManager, the REAL
// sqlite store, the REAL network-resources manager, the REAL provisioner adapter
// and the REAL jit.Manager — no fakes — and drives the whole grant path:
//
//	CreatePolicy (two resources) → RequestAccess → Approve → (assert active &
//	provisioned & propagated) → SweepOnce(expired) → (assert membership removed).
//
// If any wiring is wrong — the provisioner adapter, the account-manager
// membership primitive, the settings read, the multi-rule access policy, or the
// store satisfying jit.Store — it fails here.
func TestJitInProcessEndToEnd(t *testing.T) {
	ctx := context.Background()

	// --- Real managers off one sqlite store (mirrors the HTTP test harness). ---
	am, _, err := createManager(t)
	require.NoError(t, err)

	ownerID := groupAdminUserID // createAccount makes this the account owner (groups.update/users.update)
	account, err := createAccount(am, "jit-e2e", ownerID, "jit-e2e.example.com")
	require.NoError(t, err)
	accountID := account.Id

	st := am.Store
	permissionsManager := permissions.NewManager(st)
	groupsManager := groups.NewManager(st, permissionsManager, am)
	resourcesManager := resources.NewManager(st, permissionsManager, groupsManager, am, nil)

	// --- Seed a regular (non-admin) requester with a connected peer. ---
	requesterID := "jit-requester"
	requester := types.NewRegularUser(requesterID, "requester@jit-e2e.example.com", "Requester")
	requester.AccountID = accountID
	require.NoError(t, st.SaveUser(ctx, requester))

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	// Register the peer under the requester via the interactive-login flow so it
	// gets a non-empty user_id (JIT propagation acts on the user's own peers).
	peer, _, _, _, err := am.AddPeer(ctx, "", "", requesterID, &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "jit-requester-host"},
	}, false)
	require.NoError(t, err)
	peerID := peer.ID

	// --- Two network resources. A parent network must exist for CreateResource's
	// GetNetworkByID check; save it straight to the store (the JIT path only ever
	// READS resources, so the network/resources need only exist). ---
	network := networkTypes.NewNetwork(accountID, "jit-e2e-net", "")
	require.NoError(t, st.SaveNetwork(ctx, network))

	resA, err := resourcesManager.CreateResource(ctx, ownerID, &resourceTypes.NetworkResource{
		AccountID: accountID, NetworkID: network.ID, Name: "jit-res-a", Address: "192.168.50.10",
	})
	require.NoError(t, err)
	resB, err := resourcesManager.CreateResource(ctx, ownerID, &resourceTypes.NetworkResource{
		AccountID: accountID, NetworkID: network.ID, Name: "jit-res-b", Address: "10.20.30.40",
	})
	require.NoError(t, err)

	// --- The JIT manager wired exactly as production wires it. ---
	prov := jitprovisioner.New(am, resourcesManager)
	jitMgr := jit.NewManager(st, prov, am, am, nil, jit.DefaultMarker, 60)

	// --- CreatePolicy targeting BOTH resources (multi-rule access policy). ---
	policy, err := jitMgr.CreatePolicy(ctx, accountID, ownerID, jit.CreateJitPolicyInput{
		Name:               "e2e-policy",
		Description:        "integration test policy",
		TargetResourceIDs:  []string{resA.ID, resB.ID},
		MaxDurationMinutes: 60,
		RequestableBy:      types.JitRequestableBy{Mode: "all"},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, policy.BackingGroupID, "policy must be provisioned with a backing group")
	require.NotEmpty(t, policy.NetbirdPolicyID, "policy must be provisioned with an access policy")
	backingGroupID := policy.BackingGroupID

	// The backing group is API-issued and JIT-owned (marker-prefixed name).
	backingGroup, err := st.GetGroupByID(ctx, store.LockingStrengthNone, accountID, backingGroupID)
	require.NoError(t, err)
	assert.Equal(t, types.GroupIssuedAPI, backingGroup.Issued)

	// The access policy exists and has ONE RULE PER TARGET RESOURCE, each with a
	// UNIQUE rule ID (the Task-4 fix) and the backing group as its Source (proving
	// Sources are not stripped and are visible to validatePolicy).
	nbPolicy, err := st.GetPolicyByID(ctx, store.LockingStrengthNone, accountID, policy.NetbirdPolicyID)
	require.NoError(t, err)
	require.Len(t, nbPolicy.Rules, 2, "one access-policy rule per target resource")
	seenRuleIDs := map[string]struct{}{}
	for _, rule := range nbPolicy.Rules {
		assert.NotEmpty(t, rule.ID)
		_, dup := seenRuleIDs[rule.ID]
		assert.False(t, dup, "each access-policy rule must have a unique ID")
		seenRuleIDs[rule.ID] = struct{}{}
		assert.Contains(t, rule.Sources, backingGroupID, "rule source must be the backing group")
	}

	requester2 := jit.Caller{UserID: requesterID, Email: requester.Email, IsAdmin: false}
	admin := jit.Caller{UserID: ownerID, Email: "owner@jit-e2e.example.com", IsAdmin: true}

	// --- RequestAccess (as the eligible regular user). ---
	grant, err := jitMgr.RequestAccess(ctx, accountID, requester2, policy.ID, 1 /*min*/, "need access")
	require.NoError(t, err)
	require.Equal(t, types.GrantStatusPending, grant.Status)

	// --- Approve (as the admin owner). ---
	approved, err := jitMgr.Approve(ctx, accountID, admin, grant.ID)
	require.NoError(t, err)
	require.Equal(t, types.GrantStatusActive, approved.Status, "approve should activate the grant")
	require.NotNil(t, approved.ExpiresAt)

	// --- ASSERT membership applied: AutoGroups + peer propagation. ---
	assert.Contains(t, autoGroupsOf(t, st, requesterID), backingGroupID,
		"requester AutoGroups must contain the backing group after approval")
	assert.True(t, groupContainsPeer(t, st, accountID, backingGroupID, peerID),
		"with propagation on, the requester's peer must be a member of the backing group")

	// --- Expire it via SweepOnce with a clock past ExpiresAt. ---
	require.NoError(t, jitMgr.SweepOnce(ctx, time.Now().UTC().Add(2*time.Minute)))

	expired, err := st.GetJitGrantByID(ctx, accountID, grant.ID)
	require.NoError(t, err)
	assert.Equal(t, types.GrantStatusExpired, expired.Status, "sweep must expire the due grant")

	// --- ASSERT membership removed (both AutoGroups and peer). ---
	assert.NotContains(t, autoGroupsOf(t, st, requesterID), backingGroupID,
		"backing group must be gone from AutoGroups after expiry")
	assert.False(t, groupContainsPeer(t, st, accountID, backingGroupID, peerID),
		"the requester's peer must no longer be in the backing group after expiry")
}

// autoGroupsOf reads the user's AutoGroups straight from the store.
func autoGroupsOf(t *testing.T, st store.Store, userID string) []string {
	t.Helper()
	user, err := st.GetUserByUserID(context.Background(), store.LockingStrengthNone, userID)
	require.NoError(t, err)
	return user.AutoGroups
}

// groupContainsPeer reports whether the group has the given peer.
func groupContainsPeer(t *testing.T, st store.Store, accountID, groupID, peerID string) bool {
	t.Helper()
	group, err := st.GetGroupByID(context.Background(), store.LockingStrengthNone, accountID, groupID)
	require.NoError(t, err)
	return slices.Contains(group.Peers, peerID)
}
