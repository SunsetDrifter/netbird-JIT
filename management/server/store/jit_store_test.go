package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

// newTestJitPolicy returns a minimal valid JitPolicy for tests.
func newTestJitPolicy(accountID string) *types.JitPolicy {
	return &types.JitPolicy{
		ID:        uuid.New().String(),
		AccountID: accountID,
		Name:      "Test Policy",
		Description: "A test JIT policy",
		TargetResourceIDs: []string{"res-1", "res-2"},
		Traffic: types.JitTraffic{
			Protocol: "tcp",
			Ports:    []string{"443", "8080"},
		},
		MaxDurationMinutes: 60,
		RequestableBy:      types.JitRequestableBy{Mode: "all"},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
		PendingTTLMinutes:  30,
		Enabled:            true,
		CreatedByUserID:    "user-1",
		CreatedByEmail:     "user@example.com",
		CreatedAt:          time.Now().UTC().Truncate(time.Second),
		UpdatedAt:          time.Now().UTC().Truncate(time.Second),
	}
}

// newTestJitGrant returns a minimal valid JitGrant for tests.
func newTestJitGrant(accountID, policyID string) *types.JitGrant {
	now := time.Now().UTC().Truncate(time.Second)
	pendingExpires := now.Add(30 * time.Minute)
	return &types.JitGrant{
		ID:                       uuid.New().String(),
		AccountID:                accountID,
		PolicyID:                 policyID,
		RequesterUserID:          "requester-1",
		RequesterEmail:           "requester@example.com",
		RequestedDurationMinutes: 60,
		Justification:            "Need access for deployment",
		Status:                   types.GrantStatusPending,
		RequestedAt:              now,
		PendingExpiresAt:         &pendingExpires,
	}
}

func TestJitPolicy_RoundTrip(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-jit-test"

		policy := newTestJitPolicy(accountID)

		// Save
		err := store.SaveJitPolicy(ctx, policy)
		require.NoError(t, err)

		// Get by ID
		got, err := store.GetJitPolicyByID(ctx, accountID, policy.ID)
		require.NoError(t, err)
		assert.Equal(t, policy.ID, got.ID)
		assert.Equal(t, policy.AccountID, got.AccountID)
		assert.Equal(t, policy.Name, got.Name)
		assert.Equal(t, policy.Description, got.Description)
		assert.Equal(t, policy.TargetResourceIDs, got.TargetResourceIDs)
		assert.Equal(t, policy.Traffic.Protocol, got.Traffic.Protocol)
		assert.Equal(t, policy.Traffic.Ports, got.Traffic.Ports)
		assert.Equal(t, policy.MaxDurationMinutes, got.MaxDurationMinutes)
		assert.Equal(t, policy.RequestableBy.Mode, got.RequestableBy.Mode)
		assert.Equal(t, policy.ApproverCriteria.Mode, got.ApproverCriteria.Mode)
		assert.Equal(t, policy.PendingTTLMinutes, got.PendingTTLMinutes)
		assert.Equal(t, policy.Enabled, got.Enabled)
		assert.Equal(t, policy.CreatedByUserID, got.CreatedByUserID)
		assert.Equal(t, policy.CreatedByEmail, got.CreatedByEmail)

		// List
		policies, err := store.ListJitPolicies(ctx, accountID)
		require.NoError(t, err)
		assert.Len(t, policies, 1)
		assert.Equal(t, policy.ID, policies[0].ID)

		// Update
		policy.Name = "Updated Policy"
		err = store.SaveJitPolicy(ctx, policy)
		require.NoError(t, err)

		got2, err := store.GetJitPolicyByID(ctx, accountID, policy.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Policy", got2.Name)

		// Delete
		err = store.DeleteJitPolicy(ctx, accountID, policy.ID)
		require.NoError(t, err)

		_, err = store.GetJitPolicyByID(ctx, accountID, policy.ID)
		assert.Error(t, err)

		// List after delete
		policies, err = store.ListJitPolicies(ctx, accountID)
		require.NoError(t, err)
		assert.Len(t, policies, 0)
	})
}

func TestJitPolicy_SourcePolicyFields_RoundTrip(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-jit-mirror-test"

		// A mirror-type JIT policy: no target resources, but linked to a source
		// access-control policy with a captured name + fingerprint snapshot.
		policy := newTestJitPolicy(accountID)
		policy.TargetResourceIDs = nil
		policy.SourcePolicyID = "acl-policy-123"
		policy.SourcePolicyName = "Engineers → prod-db"
		policy.SourceFingerprint = "sha256:deadbeefcafe"

		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		got, err := store.GetJitPolicyByID(ctx, accountID, policy.ID)
		require.NoError(t, err)
		assert.Equal(t, "acl-policy-123", got.SourcePolicyID)
		assert.Equal(t, "Engineers → prod-db", got.SourcePolicyName)
		assert.Equal(t, "sha256:deadbeefcafe", got.SourceFingerprint)

		// Re-sync semantics: the snapshot fields can be updated in place.
		policy.SourcePolicyName = "Engineers → prod-db (renamed)"
		policy.SourceFingerprint = "sha256:0001"
		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		got2, err := store.GetJitPolicyByID(ctx, accountID, policy.ID)
		require.NoError(t, err)
		assert.Equal(t, "Engineers → prod-db (renamed)", got2.SourcePolicyName)
		assert.Equal(t, "sha256:0001", got2.SourceFingerprint)

		// A resource-based policy leaves the source fields empty.
		resourceBased := newTestJitPolicy(accountID)
		require.NoError(t, store.SaveJitPolicy(ctx, resourceBased))
		gotRB, err := store.GetJitPolicyByID(ctx, accountID, resourceBased.ID)
		require.NoError(t, err)
		assert.Empty(t, gotRB.SourcePolicyID)
		assert.Empty(t, gotRB.SourcePolicyName)
		assert.Empty(t, gotRB.SourceFingerprint)
	})
}

func TestJitGrant_RoundTrip(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-jit-grant-test"

		// Create a policy first (FK)
		policy := newTestJitPolicy(accountID)
		err := store.SaveJitPolicy(ctx, policy)
		require.NoError(t, err)

		grant := newTestJitGrant(accountID, policy.ID)

		// Create
		err = store.CreateJitGrant(ctx, grant)
		require.NoError(t, err)

		// Get by ID
		got, err := store.GetJitGrantByID(ctx, accountID, grant.ID)
		require.NoError(t, err)
		assert.Equal(t, grant.ID, got.ID)
		assert.Equal(t, grant.AccountID, got.AccountID)
		assert.Equal(t, grant.PolicyID, got.PolicyID)
		assert.Equal(t, grant.RequesterUserID, got.RequesterUserID)
		assert.Equal(t, grant.Status, got.Status)
		assert.Equal(t, grant.RequestedDurationMinutes, got.RequestedDurationMinutes)
		assert.Equal(t, grant.Justification, got.Justification)

		// List by requester
		grants, err := store.ListJitGrantsByRequester(ctx, accountID, grant.RequesterUserID)
		require.NoError(t, err)
		assert.Len(t, grants, 1)
		assert.Equal(t, grant.ID, grants[0].ID)

		// List by account (all statuses)
		allGrants, err := store.ListJitGrantsByAccount(ctx, accountID, "")
		require.NoError(t, err)
		assert.Len(t, allGrants, 1)

		// List by account with status filter
		pendingGrants, err := store.ListJitGrantsByAccount(ctx, accountID, types.GrantStatusPending)
		require.NoError(t, err)
		assert.Len(t, pendingGrants, 1)

		activeGrants, err := store.ListJitGrantsByAccount(ctx, accountID, types.GrantStatusActive)
		require.NoError(t, err)
		assert.Len(t, activeGrants, 0)
	})
}

func TestJitGrant_SupersedesGrantID(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-supersede-test"

		policy := newTestJitPolicy(accountID)
		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		original := newTestJitGrant(accountID, policy.ID)
		require.NoError(t, store.CreateJitGrant(ctx, original))

		renewal := newTestJitGrant(accountID, policy.ID)
		renewal.SupersedesGrantID = &original.ID
		require.NoError(t, store.CreateJitGrant(ctx, renewal))

		got, err := store.GetJitGrantByID(ctx, accountID, renewal.ID)
		require.NoError(t, err)
		require.NotNil(t, got.SupersedesGrantID)
		assert.Equal(t, original.ID, *got.SupersedesGrantID)
	})
}

func TestGetActiveJitGrantFor(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-active-grant-test"

		policy := newTestJitPolicy(accountID)
		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		grant := newTestJitGrant(accountID, policy.ID)
		grant.Status = types.GrantStatusActive
		expiresAt := time.Now().UTC().Add(1 * time.Hour).Truncate(time.Second)
		grant.ExpiresAt = &expiresAt
		require.NoError(t, store.CreateJitGrant(ctx, grant))

		// Should find active grant
		found, err := store.GetActiveJitGrantFor(ctx, accountID, grant.RequesterUserID, policy.ID)
		require.NoError(t, err)
		require.NotNil(t, found)
		assert.Equal(t, grant.ID, found.ID)

		// Different user - should not find
		notFound, err := store.GetActiveJitGrantFor(ctx, accountID, "other-user", policy.ID)
		require.NoError(t, err)
		assert.Nil(t, notFound)
	})
}

func TestListActiveJitGrantsExpiringBefore(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-expiry-test"

		policy := newTestJitPolicy(accountID)
		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		// Grant expiring soon
		grant := newTestJitGrant(accountID, policy.ID)
		grant.Status = types.GrantStatusActive
		expiresAt := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
		grant.ExpiresAt = &expiresAt
		require.NoError(t, store.CreateJitGrant(ctx, grant))

		// Grant expiring far in the future
		futureGrant := newTestJitGrant(accountID, policy.ID)
		futureGrant.Status = types.GrantStatusActive
		futureExpiresAt := time.Now().UTC().Add(10 * time.Hour).Truncate(time.Second)
		futureGrant.ExpiresAt = &futureExpiresAt
		require.NoError(t, store.CreateJitGrant(ctx, futureGrant))

		// Query for grants expiring in next 30 minutes
		threshold := time.Now().UTC().Add(30 * time.Minute)
		expiring, err := store.ListActiveJitGrantsExpiringBefore(ctx, threshold)
		require.NoError(t, err)
		assert.Len(t, expiring, 1)
		assert.Equal(t, grant.ID, expiring[0].ID)
	})
}

func TestListPendingJitGrantsExpiringBefore(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-pending-expiry-test"

		policy := newTestJitPolicy(accountID)
		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		// Pending grant expiring soon
		grant := newTestJitGrant(accountID, policy.ID)
		pendingExpires := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
		grant.PendingExpiresAt = &pendingExpires
		require.NoError(t, store.CreateJitGrant(ctx, grant))

		// Pending grant expiring far future
		futureGrant := newTestJitGrant(accountID, policy.ID)
		futurePendingExpires := time.Now().UTC().Add(10 * time.Hour).Truncate(time.Second)
		futureGrant.PendingExpiresAt = &futurePendingExpires
		require.NoError(t, store.CreateJitGrant(ctx, futureGrant))

		threshold := time.Now().UTC().Add(30 * time.Minute)
		expiring, err := store.ListPendingJitGrantsExpiringBefore(ctx, threshold)
		require.NoError(t, err)
		assert.Len(t, expiring, 1)
		assert.Equal(t, grant.ID, expiring[0].ID)
	})
}

func TestActiveGrantUserIDsForPolicy(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-active-users-test"

		policy := newTestJitPolicy(accountID)
		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		// Two active grants for different users
		grant1 := newTestJitGrant(accountID, policy.ID)
		grant1.Status = types.GrantStatusActive
		grant1.RequesterUserID = "user-a"
		expiresAt := time.Now().UTC().Add(1 * time.Hour).Truncate(time.Second)
		grant1.ExpiresAt = &expiresAt
		require.NoError(t, store.CreateJitGrant(ctx, grant1))

		grant2 := newTestJitGrant(accountID, policy.ID)
		grant2.Status = types.GrantStatusActive
		grant2.RequesterUserID = "user-b"
		grant2.ExpiresAt = &expiresAt
		require.NoError(t, store.CreateJitGrant(ctx, grant2))

		// One pending grant
		pending := newTestJitGrant(accountID, policy.ID)
		pending.RequesterUserID = "user-c"
		require.NoError(t, store.CreateJitGrant(ctx, pending))

		userIDs, err := store.ActiveGrantUserIDsForPolicy(ctx, accountID, policy.ID)
		require.NoError(t, err)
		assert.Len(t, userIDs, 2)
		assert.ElementsMatch(t, []string{"user-a", "user-b"}, userIDs)
	})
}

// TestTransitionJitGrantStatus tests the compare-and-set atomic transition.
func TestTransitionJitGrantStatus(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "account-transition-test"

		policy := newTestJitPolicy(accountID)
		require.NoError(t, store.SaveJitPolicy(ctx, policy))

		grant := newTestJitGrant(accountID, policy.ID)
		require.NoError(t, store.CreateJitGrant(ctx, grant))

		t.Run("success: pending -> approved", func(t *testing.T) {
			now := time.Now().UTC()
			patch := types.JitGrantPatch{
				ApproverUserID: strPtr("approver-1"),
				ApproverEmail:  strPtr("approver@example.com"),
				DecidedAt:      &now,
			}

			updated, ok, err := store.TransitionJitGrantStatus(
				ctx, grant.ID,
				types.GrantStatusPending,
				types.GrantStatusApproved,
				patch,
			)
			require.NoError(t, err)
			assert.True(t, ok, "expected transition to succeed")
			require.NotNil(t, updated)
			assert.Equal(t, types.GrantStatusApproved, updated.Status)
			assert.Equal(t, "approver-1", *updated.ApproverUserID)
		})

		t.Run("lost race: wrong from status returns ok=false", func(t *testing.T) {
			// Grant is now approved; trying pending -> approved again should fail
			patch := types.JitGrantPatch{}
			updated, ok, err := store.TransitionJitGrantStatus(
				ctx, grant.ID,
				types.GrantStatusPending, // wrong: it's already approved
				types.GrantStatusApproved,
				patch,
			)
			require.NoError(t, err)
			assert.False(t, ok, "expected transition to fail (lost race)")
			assert.Nil(t, updated)
		})

		t.Run("approved -> active", func(t *testing.T) {
			now := time.Now().UTC()
			expiresAt := now.Add(1 * time.Hour)
			patch := types.JitGrantPatch{
				ActivatedAt: &now,
				ExpiresAt:   &expiresAt,
			}

			updated, ok, err := store.TransitionJitGrantStatus(
				ctx, grant.ID,
				types.GrantStatusApproved,
				types.GrantStatusActive,
				patch,
			)
			require.NoError(t, err)
			assert.True(t, ok)
			require.NotNil(t, updated)
			assert.Equal(t, types.GrantStatusActive, updated.Status)
			require.NotNil(t, updated.ExpiresAt)
		})
	})
}

// TestTransitionJitGrantStatus_NonExistent ensures a non-existent grant returns ok=false.
func TestTransitionJitGrantStatus_NonExistent(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		updated, ok, err := store.TransitionJitGrantStatus(
			ctx, "no-such-grant",
			types.GrantStatusPending,
			types.GrantStatusApproved,
			types.JitGrantPatch{},
		)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Nil(t, updated)
	})
}

func strPtr(s string) *string { return &s }
