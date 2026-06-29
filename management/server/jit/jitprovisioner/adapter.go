// Package jitprovisioner adapts the real NetBird account and network-resources
// managers to the narrow provisioner interface the JIT package consumes.
//
// It lives in its own leaf package (importing only the account and resources
// manager interfaces plus shared types) so it is free of the management/server
// package and can be reused both by the server bootstrap (production wiring) and
// by the in-process integration test — neither of which could otherwise share a
// single adapter without an import cycle.
package jitprovisioner

import (
	"context"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/types"
)

// groupAndPolicyOps is the slice of account.Manager the JIT provisioner needs:
// create/delete the backing group and create/delete the access policy. Keeping
// it as a narrow interface (rather than the whole account.Manager) documents
// exactly what the adapter touches and lets tests substitute a fake.
type groupAndPolicyOps interface {
	CreateGroup(ctx context.Context, accountID, userID string, newGroup *types.Group) error
	DeleteGroup(ctx context.Context, accountID, userID, groupID string) error
	SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy, create bool) (*types.Policy, error)
	DeletePolicy(ctx context.Context, accountID, policyID, userID string) error
	GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error)
}

// resourceLookup is the slice of the network-resources manager the JIT
// provisioner needs: enumerate the account's resources so each target
// resource's Type (host/subnet/domain) can be resolved for the access-policy
// rule's DestinationResource.
type resourceLookup interface {
	GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*resourceTypes.NetworkResource, error)
}

// Adapter implements the JIT package's (unexported) provisioner interface by
// delegating each call to the real managers. The backing-group and access-policy
// mutations go to the account manager; the resource enumeration goes to the
// network-resources manager. Every call is account- and user-scoped: the userID
// flows from the JIT operation that triggered provisioning, so the underlying
// managers run their own permission checks against that user.
type Adapter struct {
	account   groupAndPolicyOps
	resources resourceLookup
}

// New builds a provisioner adapter from the real account and resources managers.
// account.Manager satisfies groupAndPolicyOps; resources.Manager satisfies
// resourceLookup.
func New(accountManager account.Manager, resourcesManager resources.Manager) *Adapter {
	return &Adapter{account: accountManager, resources: resourcesManager}
}

// CreateGroup delegates to the account manager. On create with an empty ID the
// account manager assigns a new xid and writes it back into newGroup.ID.
func (a *Adapter) CreateGroup(ctx context.Context, accountID, userID string, newGroup *types.Group) error {
	return a.account.CreateGroup(ctx, accountID, userID, newGroup)
}

// DeleteGroup delegates to the account manager.
func (a *Adapter) DeleteGroup(ctx context.Context, accountID, userID, groupID string) error {
	return a.account.DeleteGroup(ctx, accountID, userID, groupID)
}

// SavePolicy delegates to the account manager (create==true creates, false updates).
func (a *Adapter) SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy, create bool) (*types.Policy, error) {
	return a.account.SavePolicy(ctx, accountID, userID, policy, create)
}

// DeletePolicy delegates to the account manager.
func (a *Adapter) DeletePolicy(ctx context.Context, accountID, policyID, userID string) error {
	return a.account.DeletePolicy(ctx, accountID, policyID, userID)
}

// GetPolicy delegates to the account manager so JIT can read the source policy
// a mirror-type JIT policy is based on. The account manager runs its own
// permission check against userID.
func (a *Adapter) GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error) {
	return a.account.GetPolicy(ctx, accountID, policyID, userID)
}

// GetAllResourcesInAccount delegates to the network-resources manager so the JIT
// provisioner can resolve each target resource's Type for the policy rule.
func (a *Adapter) GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*resourceTypes.NetworkResource, error) {
	return a.resources.GetAllResourcesInAccount(ctx, accountID, userID)
}
