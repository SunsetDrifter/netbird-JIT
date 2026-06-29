package store

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// SaveJitPolicy upserts a JitPolicy (insert or update all columns).
func (s *SqlStore) SaveJitPolicy(ctx context.Context, policy *types.JitPolicy) error {
	result := s.db.WithContext(ctx).Save(policy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save JIT policy %s: %v", policy.ID, result.Error)
		return status.Errorf(status.Internal, "failed to save JIT policy")
	}
	return nil
}

// GetJitPolicyByID fetches a JitPolicy by account and policy ID.
func (s *SqlStore) GetJitPolicyByID(ctx context.Context, accountID, policyID string) (*types.JitPolicy, error) {
	var policy types.JitPolicy
	result := s.db.WithContext(ctx).
		Where(accountAndIDQueryCondition, accountID, policyID).
		First(&policy)
	if result.Error != nil {
		if isNotFound(result.Error) {
			return nil, status.Errorf(status.NotFound, "JIT policy %s not found", policyID)
		}
		log.WithContext(ctx).Errorf("failed to get JIT policy %s: %v", policyID, result.Error)
		return nil, status.Errorf(status.Internal, "failed to get JIT policy")
	}
	return &policy, nil
}

// ListJitPolicies returns all JitPolicies for an account.
func (s *SqlStore) ListJitPolicies(ctx context.Context, accountID string) ([]*types.JitPolicy, error) {
	var policies []*types.JitPolicy
	result := s.db.WithContext(ctx).
		Where(accountIDCondition, accountID).
		Find(&policies)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list JIT policies for account %s: %v", accountID, result.Error)
		return nil, status.Errorf(status.Internal, "failed to list JIT policies")
	}
	return policies, nil
}

// DeleteJitPolicy deletes a JitPolicy by account and policy ID.
func (s *SqlStore) DeleteJitPolicy(ctx context.Context, accountID, policyID string) error {
	result := s.db.WithContext(ctx).
		Where(accountAndIDQueryCondition, accountID, policyID).
		Delete(&types.JitPolicy{})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete JIT policy %s: %v", policyID, result.Error)
		return status.Errorf(status.Internal, "failed to delete JIT policy")
	}
	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "JIT policy %s not found", policyID)
	}
	return nil
}

// CreateJitGrant inserts a new JitGrant row.
func (s *SqlStore) CreateJitGrant(ctx context.Context, grant *types.JitGrant) error {
	result := s.db.WithContext(ctx).Create(grant)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create JIT grant %s: %v", grant.ID, result.Error)
		return status.Errorf(status.Internal, "failed to create JIT grant")
	}
	return nil
}

// GetJitGrantByID fetches a JitGrant by account and grant ID.
func (s *SqlStore) GetJitGrantByID(ctx context.Context, accountID, grantID string) (*types.JitGrant, error) {
	var grant types.JitGrant
	result := s.db.WithContext(ctx).
		Where(accountAndIDQueryCondition, accountID, grantID).
		First(&grant)
	if result.Error != nil {
		if isNotFound(result.Error) {
			return nil, status.Errorf(status.NotFound, "JIT grant %s not found", grantID)
		}
		log.WithContext(ctx).Errorf("failed to get JIT grant %s: %v", grantID, result.Error)
		return nil, status.Errorf(status.Internal, "failed to get JIT grant")
	}
	return &grant, nil
}

// ListJitGrantsByRequester returns all JitGrants for a specific requester within an account.
func (s *SqlStore) ListJitGrantsByRequester(ctx context.Context, accountID, requesterUserID string) ([]*types.JitGrant, error) {
	var grants []*types.JitGrant
	result := s.db.WithContext(ctx).
		Where("account_id = ? AND requester_user_id = ?", accountID, requesterUserID).
		Order("requested_at DESC").
		Find(&grants)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list JIT grants for requester %s: %v", requesterUserID, result.Error)
		return nil, status.Errorf(status.Internal, "failed to list JIT grants")
	}
	return grants, nil
}

// ListJitGrantsByAccount returns JitGrants for an account. Pass an empty status to list all.
func (s *SqlStore) ListJitGrantsByAccount(ctx context.Context, accountID string, grantStatus types.GrantStatus) ([]*types.JitGrant, error) {
	var grants []*types.JitGrant
	q := s.db.WithContext(ctx).Where(accountIDCondition, accountID)
	if grantStatus != "" {
		q = q.Where("status = ?", grantStatus)
	}
	result := q.Order("requested_at DESC").Find(&grants)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list JIT grants for account %s: %v", accountID, result.Error)
		return nil, status.Errorf(status.Internal, "failed to list JIT grants")
	}
	return grants, nil
}

// GetActiveJitGrantFor returns the active JitGrant for a given user+policy, or nil if none exists.
func (s *SqlStore) GetActiveJitGrantFor(ctx context.Context, accountID, requesterUserID, policyID string) (*types.JitGrant, error) {
	var grant types.JitGrant
	result := s.db.WithContext(ctx).
		Where("account_id = ? AND requester_user_id = ? AND policy_id = ? AND status = ?",
			accountID, requesterUserID, policyID, types.GrantStatusActive).
		First(&grant)
	if result.Error != nil {
		if isNotFound(result.Error) {
			return nil, nil
		}
		log.WithContext(ctx).Errorf("failed to get active JIT grant for user %s policy %s: %v", requesterUserID, policyID, result.Error)
		return nil, status.Errorf(status.Internal, "failed to get active JIT grant")
	}
	return &grant, nil
}

// ListActiveJitGrantsExpiringBefore returns all active grants whose expires_at is before the threshold.
func (s *SqlStore) ListActiveJitGrantsExpiringBefore(ctx context.Context, threshold time.Time) ([]*types.JitGrant, error) {
	var grants []*types.JitGrant
	result := s.db.WithContext(ctx).
		Where("status = ? AND expires_at IS NOT NULL AND expires_at < ?", types.GrantStatusActive, threshold).
		Find(&grants)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list expiring active JIT grants: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to list expiring JIT grants")
	}
	return grants, nil
}

// ListPendingJitGrantsExpiringBefore returns all pending grants whose pending_expires_at is before the threshold.
func (s *SqlStore) ListPendingJitGrantsExpiringBefore(ctx context.Context, threshold time.Time) ([]*types.JitGrant, error) {
	var grants []*types.JitGrant
	result := s.db.WithContext(ctx).
		Where("status = ? AND pending_expires_at IS NOT NULL AND pending_expires_at < ?", types.GrantStatusPending, threshold).
		Find(&grants)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list expiring pending JIT grants: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to list expiring pending JIT grants")
	}
	return grants, nil
}

// ListFailedJitGrants returns all failed grants across all accounts. It is used
// by the global expiry sweeper to retry grants whose membership apply failed at
// approval time. No accountID filter — the sweep is intentionally cross-account.
func (s *SqlStore) ListFailedJitGrants(ctx context.Context) ([]*types.JitGrant, error) {
	var grants []*types.JitGrant
	result := s.db.WithContext(ctx).
		Where("status = ?", types.GrantStatusFailed).
		Find(&grants)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list failed JIT grants: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to list failed JIT grants")
	}
	return grants, nil
}

// ActiveGrantUserIDsForPolicy returns the requester_user_ids of all active grants for a policy.
func (s *SqlStore) ActiveGrantUserIDsForPolicy(ctx context.Context, accountID, policyID string) ([]string, error) {
	var userIDs []string
	result := s.db.WithContext(ctx).
		Model(&types.JitGrant{}).
		Select("requester_user_id").
		Where("account_id = ? AND policy_id = ? AND status = ?", accountID, policyID, types.GrantStatusActive).
		Scan(&userIDs)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get active grant user IDs for policy %s: %v", policyID, result.Error)
		return nil, status.Errorf(status.Internal, "failed to get active grant user IDs")
	}
	return userIDs, nil
}

// TransitionJitGrantStatus is a compare-and-set atomic transition.
// It executes: UPDATE jit_grants SET status=to, <patch fields> WHERE id=grantID AND status=from.
// Returns (updated, true, nil) on success; (nil, false, nil) when zero rows matched (lost race).
func (s *SqlStore) TransitionJitGrantStatus(ctx context.Context, grantID string, from, to types.GrantStatus, patch types.JitGrantPatch) (*types.JitGrant, bool, error) {
	updates := buildJitGrantUpdates(to, patch)

	result := s.db.WithContext(ctx).
		Model(&types.JitGrant{}).
		Where("id = ? AND status = ?", grantID, from).
		Updates(updates)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to transition JIT grant %s %s->%s: %v", grantID, from, to, result.Error)
		return nil, false, status.Errorf(status.Internal, "failed to transition JIT grant status")
	}
	if result.RowsAffected == 0 {
		return nil, false, nil
	}

	// Re-fetch the updated row to return the full state.
	var updated types.JitGrant
	if err := s.db.WithContext(ctx).Where("id = ?", grantID).First(&updated).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to re-fetch JIT grant %s after transition: %v", grantID, err)
		return nil, false, status.Errorf(status.Internal, "failed to re-fetch JIT grant after transition")
	}
	return &updated, true, nil
}

// buildJitGrantUpdates converts a JitGrantPatch into a map suitable for gorm Updates.
// Using a map ensures zero-value fields are not skipped by gorm's struct update logic.
func buildJitGrantUpdates(to types.GrantStatus, patch types.JitGrantPatch) map[string]any {
	m := map[string]any{
		"status": to,
	}
	if patch.ApproverUserID != nil {
		m["approver_user_id"] = patch.ApproverUserID
	}
	if patch.ApproverEmail != nil {
		m["approver_email"] = patch.ApproverEmail
	}
	if patch.DenialReason != nil {
		m["denial_reason"] = patch.DenialReason
	}
	if patch.RevokeReason != nil {
		m["revoke_reason"] = patch.RevokeReason
	}
	if patch.DecidedAt != nil {
		m["decided_at"] = patch.DecidedAt
	}
	if patch.ActivatedAt != nil {
		m["activated_at"] = patch.ActivatedAt
	}
	if patch.ExpiresAt != nil {
		m["expires_at"] = patch.ExpiresAt
	}
	if patch.RevokedAt != nil {
		m["revoked_at"] = patch.RevokedAt
	}
	if patch.LastError != nil {
		m["last_error"] = patch.LastError
	}
	return m
}

// isNotFound returns true when err represents a gorm record-not-found error.
func isNotFound(err error) bool {
	return err != nil && err == gorm.ErrRecordNotFound
}
