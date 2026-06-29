package jit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	jithandler "github.com/netbirdio/netbird/management/server/http/handlers/jit"
	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ---------------------------------------------------------------------------
// Fake: jit.JitManager
// ---------------------------------------------------------------------------

type fakeJitManager struct {
	createPolicyFunc         func(ctx context.Context, accountID, userID string, in jit.CreateJitPolicyInput) (*types.JitPolicy, error)
	listPoliciesFunc         func(ctx context.Context, accountID string) ([]*types.JitPolicy, error)
	listEligiblePoliciesFunc func(ctx context.Context, accountID string, caller jit.Caller) ([]*types.JitPolicy, error)
	requestAccessFunc        func(ctx context.Context, accountID string, caller jit.Caller, policyID string, dur int, just string) (*types.JitGrant, error)
	listMineFunc             func(ctx context.Context, accountID string, caller jit.Caller, s *types.GrantStatus) ([]*types.JitGrant, error)
	listGrantsFunc           func(ctx context.Context, accountID string, s types.GrantStatus) ([]*types.JitGrant, error)
	sourceDriftFunc          func(ctx context.Context, accountID, userID string, p *types.JitPolicy) (bool, bool)
}

func (f *fakeJitManager) CreatePolicy(ctx context.Context, accountID, userID string, in jit.CreateJitPolicyInput) (*types.JitPolicy, error) {
	return f.createPolicyFunc(ctx, accountID, userID, in)
}
func (f *fakeJitManager) UpdatePolicy(_ context.Context, _, _, _ string, _ jit.UpdateJitPolicyInput) (*types.JitPolicy, error) {
	return nil, nil
}
func (f *fakeJitManager) DeletePolicy(_ context.Context, _, _, _ string) error { return nil }
func (f *fakeJitManager) GetPolicy(_ context.Context, _, _ string) (*types.JitPolicy, error) {
	return nil, status.Errorf(status.NotFound, "not found")
}
func (f *fakeJitManager) ListPolicies(ctx context.Context, accountID string) ([]*types.JitPolicy, error) {
	if f.listPoliciesFunc != nil {
		return f.listPoliciesFunc(ctx, accountID)
	}
	return nil, nil
}
func (f *fakeJitManager) ListEligiblePolicies(ctx context.Context, accountID string, caller jit.Caller) ([]*types.JitPolicy, error) {
	if f.listEligiblePoliciesFunc != nil {
		return f.listEligiblePoliciesFunc(ctx, accountID, caller)
	}
	return nil, nil
}
func (f *fakeJitManager) RequestAccess(ctx context.Context, accountID string, caller jit.Caller, policyID string, dur int, just string) (*types.JitGrant, error) {
	if f.requestAccessFunc != nil {
		return f.requestAccessFunc(ctx, accountID, caller, policyID, dur, just)
	}
	return nil, nil
}
func (f *fakeJitManager) ListMine(ctx context.Context, accountID string, caller jit.Caller, s *types.GrantStatus) ([]*types.JitGrant, error) {
	if f.listMineFunc != nil {
		return f.listMineFunc(ctx, accountID, caller, s)
	}
	return nil, nil
}
func (f *fakeJitManager) Cancel(_ context.Context, _ string, _ jit.Caller, _ string) (*types.JitGrant, error) {
	return nil, nil
}
func (f *fakeJitManager) EndEarly(_ context.Context, _ string, _ jit.Caller, _ string) (*types.JitGrant, error) {
	return nil, nil
}
func (f *fakeJitManager) Approve(_ context.Context, _ string, _ jit.Caller, _ string) (*types.JitGrant, error) {
	return nil, nil
}
func (f *fakeJitManager) Deny(_ context.Context, _ string, _ jit.Caller, _, _ string) (*types.JitGrant, error) {
	return nil, nil
}
func (f *fakeJitManager) Revoke(_ context.Context, _ string, _ jit.Caller, _, _ string) (*types.JitGrant, error) {
	return nil, nil
}
func (f *fakeJitManager) ExtendByAdmin(_ context.Context, _ string, _ jit.Caller, _ string, _ int) (*types.JitGrant, error) {
	return nil, nil
}
func (f *fakeJitManager) ListGrants(ctx context.Context, accountID string, s types.GrantStatus) ([]*types.JitGrant, error) {
	if f.listGrantsFunc != nil {
		return f.listGrantsFunc(ctx, accountID, s)
	}
	return nil, nil
}
func (f *fakeJitManager) SourceDriftStatus(ctx context.Context, accountID, userID string, p *types.JitPolicy) (bool, bool) {
	if f.sourceDriftFunc != nil {
		return f.sourceDriftFunc(ctx, accountID, userID, p)
	}
	return false, false
}

// ---------------------------------------------------------------------------
// Fake: permissions.Manager (minimal — only ValidateUserPermissions is called)
// ---------------------------------------------------------------------------

type fakePerms struct {
	allow bool // ValidateUserPermissions result (and ValidateRoleModuleAccess default)
	// roleAccess, when non-nil, overrides ValidateRoleModuleAccess independently
	// of allow — lets a test simulate the upstream service-user Read bypass
	// (ValidateUserPermissions=true) while the caller's role denies access.
	roleAccess *bool
}

func (f *fakePerms) ValidateUserPermissions(_ context.Context, _, _ string, _ modules.Module, _ operations.Operation) (bool, context.Context, error) {
	return f.allow, context.Background(), nil
}
func (f *fakePerms) ValidateRoleModuleAccess(_ context.Context, _ string, _ roles.RolePermissions, _ modules.Module, _ operations.Operation) bool {
	if f.roleAccess != nil {
		return *f.roleAccess
	}
	return f.allow
}
func (f *fakePerms) ValidateAccountAccess(ctx context.Context, _ string, _ *types.User, _ bool) (context.Context, error) {
	return ctx, nil
}
func (f *fakePerms) GetPermissionsByRole(_ context.Context, _ types.UserRole) (roles.Permissions, error) {
	return nil, nil
}
func (f *fakePerms) SetAccountManager(_ account.Manager) {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildRouter(jm *fakeJitManager, user *types.User, allow bool) *mux.Router {
	am := &mock_server.MockAccountManager{
		GetUserFromUserAuthFunc: func(_ context.Context, _ auth.UserAuth) (*types.User, error) {
			return user, nil
		},
	}
	router := mux.NewRouter()
	jithandler.AddEndpoints(jm, am, &fakePerms{allow: allow}, router)
	return router
}

func injectAuth(r *http.Request, accountID, userID string) *http.Request {
	ctx := nbcontext.SetUserAuthInContext(r.Context(), auth.UserAuth{
		AccountId: accountID,
		UserId:    userID,
	})
	return r.WithContext(ctx)
}

func doRequest(router *mux.Router, method, path string, body interface{}, accountID, userID string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req = injectAuth(req, accountID, userID)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// newRegularUser builds a types.User with the regular role (no admin power).
func newRegularUser(id string) *types.User {
	return types.NewRegularUser(id, id+"@example.com", "Test User")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestCreatePolicy_AdminCanCreate verifies that an admin POST /jit/policies
// returns 200 with a bare-JSON body (no success/data/error envelope).
func TestCreatePolicy_AdminCanCreate(t *testing.T) {
	created := &types.JitPolicy{
		ID:                 "pol1",
		AccountID:          "acc1",
		Name:               "Engineering VPN",
		TargetResourceIDs:  []string{"res1"},
		Traffic:            types.JitTraffic{Protocol: "all"},
		MaxDurationMinutes: 60,
		RequestableBy:      types.JitRequestableBy{Mode: "all"},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
		PendingTTLMinutes:  30,
		Enabled:            true,
	}

	mgr := &fakeJitManager{
		createPolicyFunc: func(_ context.Context, accountID, userID string, in jit.CreateJitPolicyInput) (*types.JitPolicy, error) {
			assert.Equal(t, "acc1", accountID)
			assert.Equal(t, "admin1", userID)
			assert.Equal(t, "Engineering VPN", in.Name)
			return created, nil
		},
	}

	router := buildRouter(mgr, types.NewAdminUser("admin1"), true)
	body := map[string]interface{}{
		"name":               "Engineering VPN",
		"targetResourceIds":  []string{"res1"},
		"maxDurationMinutes": 60,
		"requestableBy":      map[string]string{"mode": "all"},
		"approverCriteria":   map[string]string{"mode": "any_admin"},
	}
	rr := doRequest(router, http.MethodPost, "/jit/policies", body, "acc1", "admin1")

	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "pol1", resp["id"])
	assert.Equal(t, "Engineering VPN", resp["name"])
	// Bare JSON — no envelope.
	assert.NotContains(t, resp, "success")
	assert.NotContains(t, resp, "data")
	assert.NotContains(t, resp, "error")
}

// TestCreatePolicy_MirrorType_ResponseCarriesSource verifies a policy-based
// create forwards sourcePolicyId to the manager and the response carries the
// source id + snapshotted name (and fresh = no drift).
func TestCreatePolicy_MirrorType_ResponseCarriesSource(t *testing.T) {
	created := &types.JitPolicy{
		ID:                 "pol-m",
		AccountID:          "acc1",
		Name:               "DB break-glass",
		SourcePolicyID:     "acl-1",
		SourcePolicyName:   "Engineers → prod-db",
		MaxDurationMinutes: 60,
		RequestableBy:      types.JitRequestableBy{Mode: "all"},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
		Enabled:            true,
	}
	mgr := &fakeJitManager{
		createPolicyFunc: func(_ context.Context, _, _ string, in jit.CreateJitPolicyInput) (*types.JitPolicy, error) {
			assert.Equal(t, "acl-1", in.SourcePolicyID)
			assert.Empty(t, in.TargetResourceIDs)
			return created, nil
		},
	}
	router := buildRouter(mgr, types.NewAdminUser("admin1"), true)
	body := map[string]interface{}{
		"name":               "DB break-glass",
		"sourcePolicyId":     "acl-1",
		"maxDurationMinutes": 60,
		"requestableBy":      map[string]string{"mode": "all"},
		"approverCriteria":   map[string]string{"mode": "any_admin"},
	}
	rr := doRequest(router, http.MethodPost, "/jit/policies", body, "acc1", "admin1")
	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "acl-1", resp["sourcePolicyId"])
	assert.Equal(t, "Engineers → prod-db", resp["sourcePolicyName"])
	assert.Equal(t, false, resp["sourceDrifted"])
	assert.Equal(t, false, resp["sourceDeleted"])
}

// TestListPolicies_SurfacesSourceDrift verifies the admin policy list reports
// the drift the manager computes for a mirror-type policy.
func TestListPolicies_SurfacesSourceDrift(t *testing.T) {
	mirror := &types.JitPolicy{
		ID: "pol-m", AccountID: "acc1", Name: "DB break-glass",
		SourcePolicyID: "acl-1", SourcePolicyName: "Engineers → prod-db",
		Enabled:          true,
		RequestableBy:    types.JitRequestableBy{Mode: "all"},
		ApproverCriteria: types.JitApproverCriteria{Mode: "any_admin"},
		Traffic:          types.JitTraffic{Protocol: "all"},
	}
	mgr := &fakeJitManager{
		listPoliciesFunc: func(_ context.Context, _ string) ([]*types.JitPolicy, error) {
			return []*types.JitPolicy{mirror}, nil
		},
		sourceDriftFunc: func(_ context.Context, _, _ string, _ *types.JitPolicy) (bool, bool) {
			return true, false // source changed since last sync
		},
	}
	router := buildRouter(mgr, types.NewAdminUser("admin1"), true)
	rr := doRequest(router, http.MethodGet, "/jit/policies", nil, "acc1", "admin1")
	require.Equal(t, http.StatusOK, rr.Code)

	var resp []map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp, 1)
	assert.Equal(t, true, resp[0]["sourceDrifted"])
	assert.Equal(t, false, resp[0]["sourceDeleted"])
	assert.Equal(t, "acl-1", resp[0]["sourcePolicyId"])
}

// TestCreatePolicy_NonAdminIsForbidden verifies that a user without the Jit
// module permission receives 403.
func TestCreatePolicy_NonAdminIsForbidden(t *testing.T) {
	mgr := &fakeJitManager{}
	router := buildRouter(mgr, newRegularUser("user2"), false /*deny*/)

	body := map[string]interface{}{
		"name":               "Should fail",
		"targetResourceIds":  []string{},
		"maxDurationMinutes": 60,
		"requestableBy":      map[string]string{"mode": "all"},
		"approverCriteria":   map[string]string{"mode": "any_admin"},
	}
	rr := doRequest(router, http.MethodPost, "/jit/policies", body, "acc1", "user2")
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestListEligiblePolicies_UserCanCallWithoutJitModule verifies that
// GET /jit/policies/eligible bypasses the modules.Jit gate and that the Caller
// is built from the resolved user record (groups flow through).
func TestListEligiblePolicies_UserCanCallWithoutJitModule(t *testing.T) {
	regularUser := newRegularUser("user3")
	regularUser.AutoGroups = []string{"grp1"}

	eligible := &types.JitPolicy{
		ID:                 "pol2",
		Name:               "Staging",
		TargetResourceIDs:  []string{"res2"},
		MaxDurationMinutes: 30,
		Enabled:            true,
		RequestableBy:      types.JitRequestableBy{Mode: "all"},
		ApproverCriteria:   types.JitApproverCriteria{Mode: "any_admin"},
		Traffic:            types.JitTraffic{Protocol: "tcp"},
	}

	mgr := &fakeJitManager{
		listEligiblePoliciesFunc: func(_ context.Context, accountID string, caller jit.Caller) ([]*types.JitPolicy, error) {
			assert.Equal(t, "user3", caller.UserID)
			assert.False(t, caller.IsAdmin)
			assert.Equal(t, []string{"grp1"}, caller.Groups)
			return []*types.JitPolicy{eligible}, nil
		},
	}

	// allow=false: the Jit module gate must NOT be consulted for this endpoint.
	router := buildRouter(mgr, regularUser, false)
	rr := doRequest(router, http.MethodGet, "/jit/policies/eligible", nil, "acc1", "user3")

	require.Equal(t, http.StatusOK, rr.Code)

	var resp []map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp, 1)
	assert.Equal(t, "pol2", resp[0]["id"])
}

// TestCreateRequest_UserCanSubmitWithoutJitModule verifies that
// POST /jit/requests (self-service) works for a regular user and that the
// Caller groups are correctly forwarded to the manager.
func TestCreateRequest_UserCanSubmitWithoutJitModule(t *testing.T) {
	regularUser := newRegularUser("user4")
	regularUser.AutoGroups = []string{"grp2"}

	grant := &types.JitGrant{
		ID:                       "grant1",
		PolicyID:                 "pol1",
		RequesterUserID:          "user4",
		RequestedDurationMinutes: 60,
		Status:                   types.GrantStatusPending,
	}

	mgr := &fakeJitManager{
		requestAccessFunc: func(_ context.Context, accountID string, caller jit.Caller, policyID string, dur int, just string) (*types.JitGrant, error) {
			assert.Equal(t, "user4", caller.UserID)
			assert.Equal(t, []string{"grp2"}, caller.Groups)
			assert.False(t, caller.IsAdmin)
			assert.Equal(t, "pol1", policyID)
			assert.Equal(t, 60, dur)
			return grant, nil
		},
	}

	router := buildRouter(mgr, regularUser, false /*no module grant needed*/)
	body := map[string]interface{}{
		"policyId":        "pol1",
		"durationMinutes": 60,
		"justification":   "need access for deploy",
	}
	rr := doRequest(router, http.MethodPost, "/jit/requests", body, "acc1", "user4")

	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "grant1", resp["id"])
	assert.Equal(t, "pending", resp["status"])
	assert.NotContains(t, resp, "success") // bare JSON confirmed
}

// TestAdminReads_GatedOnRoleNotServiceUserReadBypass verifies the admin read
// endpoints consult the caller's ROLE (ValidateRoleModuleAccess), not the
// permissive ValidateUserPermissions path. Even when ValidateUserPermissions
// returns true — as it does upstream for ANY service user on a Read op — a role
// that denies Jit:Read yields 403. This closes the service-user Read bypass for
// JIT, whose data reveals who-can-access-what.
func TestAdminReads_GatedOnRoleNotServiceUserReadBypass(t *testing.T) {
	denyRole := false
	am := &mock_server.MockAccountManager{
		GetUserFromUserAuthFunc: func(_ context.Context, _ auth.UserAuth) (*types.User, error) {
			return newRegularUser("svcuser"), nil
		},
	}
	router := mux.NewRouter()
	jithandler.AddEndpoints(&fakeJitManager{}, am, &fakePerms{allow: true, roleAccess: &denyRole}, router)

	for _, path := range []string{"/jit/policies", "/jit/policies/pol1", "/jit/requests?status=pending", "/jit/grants/active"} {
		rr := doRequest(router, http.MethodGet, path, nil, "acc1", "svcuser")
		assert.Equal(t, http.StatusForbidden, rr.Code, "GET %s must be role-gated", path)
	}
}

// TestListGrants_AdminWithStatusFilter verifies GET /jit/requests?status=active
// passes the status filter to the manager and returns bare-JSON list.
func TestListGrants_AdminWithStatusFilter(t *testing.T) {
	g := &types.JitGrant{
		ID:              "grant2",
		PolicyID:        "pol1",
		RequesterUserID: "someuser",
		Status:          types.GrantStatusActive,
	}

	mgr := &fakeJitManager{
		listGrantsFunc: func(_ context.Context, accountID string, s types.GrantStatus) ([]*types.JitGrant, error) {
			assert.Equal(t, "acc1", accountID)
			assert.Equal(t, types.GrantStatusActive, s)
			return []*types.JitGrant{g}, nil
		},
		listPoliciesFunc: func(_ context.Context, _ string) ([]*types.JitPolicy, error) {
			return []*types.JitPolicy{{ID: "pol1", Name: "Engineering VPN"}}, nil
		},
	}

	router := buildRouter(mgr, types.NewAdminUser("admin1"), true)
	rr := doRequest(router, http.MethodGet, "/jit/requests?status=active", nil, "acc1", "admin1")

	require.Equal(t, http.StatusOK, rr.Code)

	var resp []map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp, 1)
	assert.Equal(t, "grant2", resp[0]["id"])
	assert.Equal(t, "active", resp[0]["status"])
	assert.Equal(t, "Engineering VPN", resp[0]["policyName"]) // resolved server-side from ListPolicies
}
