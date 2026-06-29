package jit

import (
	"context"

	"github.com/netbirdio/netbird/management/server/types"
)

// Manager is the public interface the HTTP layer (Task 9) uses to reach the JIT
// subsystem. The concrete *Manager satisfies it; tests may substitute a fake.
type JitManager interface {
	// Policy CRUD (admin only).
	CreatePolicy(ctx context.Context, accountID, userID string, in CreateJitPolicyInput) (*types.JitPolicy, error)
	UpdatePolicy(ctx context.Context, accountID, userID, policyID string, patch UpdateJitPolicyInput) (*types.JitPolicy, error)
	DeletePolicy(ctx context.Context, accountID, userID, policyID string) error
	GetPolicy(ctx context.Context, accountID, policyID string) (*types.JitPolicy, error)
	ListPolicies(ctx context.Context, accountID string) ([]*types.JitPolicy, error)

	// ListEligiblePolicies returns enabled policies the caller is eligible to
	// request (IsEligible check applied).  User self-service.
	ListEligiblePolicies(ctx context.Context, accountID string, caller Caller) ([]*types.JitPolicy, error)

	// Grant / request operations.
	RequestAccess(ctx context.Context, accountID string, caller Caller, policyID string, durationMinutes int, justification string) (*types.JitGrant, error)
	ListMine(ctx context.Context, accountID string, caller Caller, status *types.GrantStatus) ([]*types.JitGrant, error)
	Cancel(ctx context.Context, accountID string, caller Caller, grantID string) (*types.JitGrant, error)
	EndEarly(ctx context.Context, accountID string, caller Caller, grantID string) (*types.JitGrant, error)

	// Admin grant operations.
	Approve(ctx context.Context, accountID string, caller Caller, grantID string) (*types.JitGrant, error)
	Deny(ctx context.Context, accountID string, caller Caller, grantID, reason string) (*types.JitGrant, error)
	Revoke(ctx context.Context, accountID string, caller Caller, grantID, reason string) (*types.JitGrant, error)
	ExtendByAdmin(ctx context.Context, accountID string, caller Caller, grantID string, durationMinutes int) (*types.JitGrant, error)

	// ListGrants returns grants for the account filtered by status ("" = all).
	// Admin list.
	ListGrants(ctx context.Context, accountID string, status types.GrantStatus) ([]*types.JitGrant, error)
}
