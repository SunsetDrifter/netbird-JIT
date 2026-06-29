package jit

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// handler holds the dependencies for all JIT HTTP endpoints.
type handler struct {
	jitManager         jit.JitManager
	accountManager     account.Manager
	permissionsManager permissions.Manager
}

// AddEndpoints registers all JIT routes on router (which is already mounted
// under /api). Admin routes are gated via permissionsManager.ValidateUserPermissions
// with modules.Jit; self-service routes are authenticated-only (the manager
// enforces eligibility/ownership internally).
func AddEndpoints(
	jitManager         jit.JitManager,
	accountManager account.Manager,
	permissionsManager permissions.Manager,
	router *mux.Router,
) {
	h := &handler{
		jitManager:         jitManager,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
	}

	// Admin: policy CRUD.
	router.HandleFunc("/jit/policies", h.listPolicies).Methods("GET", "OPTIONS")
	router.HandleFunc("/jit/policies", h.createPolicy).Methods("POST", "OPTIONS")

	// Self-service: eligible policies — registered BEFORE /{policyId} so the
	// literal "eligible" segment wins over the variable.
	router.HandleFunc("/jit/policies/eligible", h.listEligiblePolicies).Methods("GET", "OPTIONS")

	router.HandleFunc("/jit/policies/{policyId}", h.getPolicy).Methods("GET", "OPTIONS")
	router.HandleFunc("/jit/policies/{policyId}", h.updatePolicy).Methods("PUT", "OPTIONS")
	router.HandleFunc("/jit/policies/{policyId}", h.deletePolicy).Methods("DELETE", "OPTIONS")

	// Admin: request list + decisions.
	router.HandleFunc("/jit/requests", h.listRequests).Methods("GET", "OPTIONS")

	// Self-service: submit request + list mine — registered BEFORE /{grantId}/...
	router.HandleFunc("/jit/requests", h.createRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/jit/requests/mine", h.listMine).Methods("GET", "OPTIONS")

	// Mixed: admin approve/deny; self-service cancel.
	router.HandleFunc("/jit/requests/{grantId}/approve", h.approveRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/jit/requests/{grantId}/deny", h.denyRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/jit/requests/{grantId}/cancel", h.cancelRequest).Methods("POST", "OPTIONS")

	// Admin: active grant list + revoke + extend.
	router.HandleFunc("/jit/grants/active", h.listActiveGrants).Methods("GET", "OPTIONS")
	router.HandleFunc("/jit/grants/{grantId}/revoke", h.revokeGrant).Methods("POST", "OPTIONS")
	router.HandleFunc("/jit/grants/{grantId}/extend", h.extendGrant).Methods("POST", "OPTIONS")

	// Self-service: end grant early.
	router.HandleFunc("/jit/grants/{grantId}/end", h.endGrant).Methods("POST", "OPTIONS")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// requireJitPerm validates that the authenticated user has the given Jit
// module operation. Returns (accountID, userID, ok); on false the response has
// already been written.
func (h *handler) requireJitPerm(w http.ResponseWriter, r *http.Request, op operations.Operation) (accountID, userID string, ok bool) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", "", false
	}
	accountID, userID = userAuth.AccountId, userAuth.UserId

	allowed, ctx, err := h.permissionsManager.ValidateUserPermissions(r.Context(), accountID, userID, modules.Jit, op)
	if err != nil {
		util.WriteError(ctx, err, w)
		return "", "", false
	}
	if !allowed {
		util.WriteError(ctx, status.NewPermissionDeniedError(), w)
		return "", "", false
	}
	return accountID, userID, true
}

// requireJitAdminRead gates admin read endpoints on the caller's ROLE granting
// modules.Jit Read, deliberately bypassing the upstream service-user Read
// shortcut in permissions.ValidateUserPermissions (which returns true for ANY
// service user on a Read op, even role=user). JIT read data reveals who can
// access what, so it must follow the role: Owner/Admin/Auditor pass;
// User/NetworkAdmin do not. Returns (accountID, userID, ok); on false the
// response has already been written. userID is returned so read handlers can
// compute source-policy drift (a permissioned read of the source policy).
func (h *handler) requireJitAdminRead(w http.ResponseWriter, r *http.Request) (accountID, userID string, ok bool) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", "", false
	}
	accountID, userID = userAuth.AccountId, userAuth.UserId

	user, err := h.accountManager.GetUserFromUserAuth(r.Context(), userAuth)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", "", false
	}

	role, exists := roles.RolesMap[user.Role]
	if !exists {
		util.WriteError(r.Context(), status.NewPermissionDeniedError(), w)
		return "", "", false
	}
	if !h.permissionsManager.ValidateRoleModuleAccess(r.Context(), accountID, role, modules.Jit, operations.Read) {
		util.WriteError(r.Context(), status.NewPermissionDeniedError(), w)
		return "", "", false
	}
	return accountID, userID, true
}

// requireJitPermWithCaller combines a Jit-module permission check with Caller
// resolution. Used by admin handlers that need both the gate and the Caller
// for downstream approver checks. Returns (accountID, caller, ok).
func (h *handler) requireJitPermWithCaller(w http.ResponseWriter, r *http.Request, op operations.Operation) (accountID string, caller jit.Caller, ok bool) {
	accountID, _, ok = h.requireJitPerm(w, r, op)
	if !ok {
		return "", jit.Caller{}, false
	}
	accountID, caller, ok = h.callerFrom(w, r)
	return accountID, caller, ok
}

// callerFrom resolves the Jit Caller from the authenticated user record.
// The role is always sourced from NetBird (via account.Manager), never the JWT.
func (h *handler) callerFrom(w http.ResponseWriter, r *http.Request) (accountID string, caller jit.Caller, ok bool) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", jit.Caller{}, false
	}
	accountID = userAuth.AccountId

	user, err := h.accountManager.GetUserFromUserAuth(r.Context(), userAuth)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", jit.Caller{}, false
	}

	return accountID, jit.Caller{
		UserID:  user.Id,
		Email:   user.Email,
		IsAdmin: user.HasAdminPower(),
		Groups:  user.AutoGroups,
	}, true
}

// ---------------------------------------------------------------------------
// Admin: policy CRUD
// ---------------------------------------------------------------------------

func (h *handler) listPolicies(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := h.requireJitAdminRead(w, r)
	if !ok {
		return
	}
	policies, err := h.jitManager.ListPolicies(r.Context(), accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	resp := make([]policyResponse, 0, len(policies))
	for _, p := range policies {
		resp = append(resp, h.policyResp(r.Context(), accountID, userID, p))
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) createPolicy(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := h.requireJitPerm(w, r, operations.Create)
	if !ok {
		return
	}
	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if req.Name == "" {
		util.WriteErrorResponse("name is required", http.StatusBadRequest, w)
		return
	}
	in := jit.CreateJitPolicyInput{
		Name:               req.Name,
		Description:        req.Description,
		TargetResourceIDs:  req.TargetResourceIds,
		MaxDurationMinutes: req.MaxDurationMinutes,
		RequestableBy:      toRequestableBy(req.RequestableBy),
		ApproverCriteria:   toApproverCriteria(req.ApproverCriteria),
	}
	in.SourcePolicyID = req.SourcePolicyId
	if req.Traffic != nil {
		t := toTraffic(*req.Traffic)
		in.Traffic = &t
	}
	if req.PendingTtlMinutes != nil {
		in.PendingTTLMinutes = req.PendingTtlMinutes
	}
	policy, err := h.jitManager.CreatePolicy(r.Context(), accountID, userID, in)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// A freshly created policy is, by definition, in sync with its source.
	util.WriteJSONObject(r.Context(), w, toPolicyResponse(policy, false, false))
}

func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := h.requireJitAdminRead(w, r)
	if !ok {
		return
	}
	policyID := mux.Vars(r)["policyId"]
	policy, err := h.jitManager.GetPolicy(r.Context(), accountID, policyID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, h.policyResp(r.Context(), accountID, userID, policy))
}

func (h *handler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := h.requireJitPerm(w, r, operations.Update)
	if !ok {
		return
	}
	policyID := mux.Vars(r)["policyId"]
	var req updatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	patch := toPatch(req)
	policy, err := h.jitManager.UpdatePolicy(r.Context(), accountID, userID, policyID, patch)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, h.policyResp(r.Context(), accountID, userID, policy))
}

func (h *handler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := h.requireJitPerm(w, r, operations.Delete)
	if !ok {
		return
	}
	policyID := mux.Vars(r)["policyId"]
	if err := h.jitManager.DeletePolicy(r.Context(), accountID, userID, policyID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, struct{}{})
}

// ---------------------------------------------------------------------------
// Self-service: eligible policies
// ---------------------------------------------------------------------------

func (h *handler) listEligiblePolicies(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.callerFrom(w, r)
	if !ok {
		return
	}
	policies, err := h.jitManager.ListEligiblePolicies(r.Context(), accountID, caller)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	resp := make([]eligiblePolicyResponse, 0, len(policies))
	for _, p := range policies {
		resp = append(resp, toEligiblePolicyResponse(p))
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

// ---------------------------------------------------------------------------
// Admin: request list + decisions
// ---------------------------------------------------------------------------

func (h *handler) listRequests(w http.ResponseWriter, r *http.Request) {
	accountID, _, ok := h.requireJitAdminRead(w, r)
	if !ok {
		return
	}
	var grantStatus types.GrantStatus
	if s := r.URL.Query().Get("status"); s != "" {
		grantStatus = types.GrantStatus(s)
	}
	grants, err := h.jitManager.ListGrants(r.Context(), accountID, grantStatus)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	names := h.policyNames(r.Context(), accountID)
	resp := make([]grantResponse, 0, len(grants))
	for _, g := range grants {
		resp = append(resp, toGrantResponse(g, names[g.PolicyID]))
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) approveRequest(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.requireJitPermWithCaller(w, r, operations.Update)
	if !ok {
		return
	}
	grantID := mux.Vars(r)["grantId"]
	grant, err := h.jitManager.Approve(r.Context(), accountID, caller, grantID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toGrantResponse(grant, h.policyName(r.Context(), accountID, grant.PolicyID)))
}

func (h *handler) denyRequest(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.requireJitPermWithCaller(w, r, operations.Update)
	if !ok {
		return
	}
	grantID := mux.Vars(r)["grantId"]
	reason := decodeReason(r)
	grant, err := h.jitManager.Deny(r.Context(), accountID, caller, grantID, reason)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toGrantResponse(grant, h.policyName(r.Context(), accountID, grant.PolicyID)))
}

// ---------------------------------------------------------------------------
// Self-service: submit request + list mine + cancel
// ---------------------------------------------------------------------------

func (h *handler) createRequest(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.callerFrom(w, r)
	if !ok {
		return
	}
	var req createRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if req.PolicyId == "" {
		util.WriteErrorResponse("policyId is required", http.StatusBadRequest, w)
		return
	}
	if req.DurationMinutes <= 0 {
		util.WriteErrorResponse("durationMinutes must be positive", http.StatusBadRequest, w)
		return
	}
	grant, err := h.jitManager.RequestAccess(r.Context(), accountID, caller, req.PolicyId, req.DurationMinutes, req.Justification)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toGrantResponse(grant, h.policyName(r.Context(), accountID, grant.PolicyID)))
}

func (h *handler) listMine(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.callerFrom(w, r)
	if !ok {
		return
	}
	grants, err := h.jitManager.ListMine(r.Context(), accountID, caller, nil)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	names := h.policyNames(r.Context(), accountID)
	resp := make([]grantResponse, 0, len(grants))
	for _, g := range grants {
		resp = append(resp, toGrantResponse(g, names[g.PolicyID]))
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) cancelRequest(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.callerFrom(w, r)
	if !ok {
		return
	}
	grantID := mux.Vars(r)["grantId"]
	grant, err := h.jitManager.Cancel(r.Context(), accountID, caller, grantID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toGrantResponse(grant, h.policyName(r.Context(), accountID, grant.PolicyID)))
}

// ---------------------------------------------------------------------------
// Admin: grant operations
// ---------------------------------------------------------------------------

func (h *handler) listActiveGrants(w http.ResponseWriter, r *http.Request) {
	accountID, _, ok := h.requireJitAdminRead(w, r)
	if !ok {
		return
	}
	grants, err := h.jitManager.ListGrants(r.Context(), accountID, types.GrantStatusActive)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	names := h.policyNames(r.Context(), accountID)
	resp := make([]grantResponse, 0, len(grants))
	for _, g := range grants {
		resp = append(resp, toGrantResponse(g, names[g.PolicyID]))
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.requireJitPermWithCaller(w, r, operations.Update)
	if !ok {
		return
	}
	grantID := mux.Vars(r)["grantId"]
	reason := decodeReason(r)
	grant, err := h.jitManager.Revoke(r.Context(), accountID, caller, grantID, reason)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toGrantResponse(grant, h.policyName(r.Context(), accountID, grant.PolicyID)))
}

func (h *handler) extendGrant(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.requireJitPermWithCaller(w, r, operations.Update)
	if !ok {
		return
	}
	grantID := mux.Vars(r)["grantId"]
	var req extendBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if req.DurationMinutes <= 0 {
		util.WriteErrorResponse("durationMinutes must be positive", http.StatusBadRequest, w)
		return
	}
	grant, err := h.jitManager.ExtendByAdmin(r.Context(), accountID, caller, grantID, req.DurationMinutes)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toGrantResponse(grant, h.policyName(r.Context(), accountID, grant.PolicyID)))
}

// Self-service: end grant early.
func (h *handler) endGrant(w http.ResponseWriter, r *http.Request) {
	accountID, caller, ok := h.callerFrom(w, r)
	if !ok {
		return
	}
	grantID := mux.Vars(r)["grantId"]
	grant, err := h.jitManager.EndEarly(r.Context(), accountID, caller, grantID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toGrantResponse(grant, h.policyName(r.Context(), accountID, grant.PolicyID)))
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// policyNames builds a policyID→name map for the account so grant responses can
// carry PolicyName. Non-admins can't list policies, but this is a server-side
// lookup that runs regardless of the caller's role — it only surfaces the names
// of policies the caller already has grants for. On error it returns an empty
// map; PolicyName is omitempty, so the client degrades gracefully.
func (h *handler) policyNames(ctx context.Context, accountID string) map[string]string {
	policies, err := h.jitManager.ListPolicies(ctx, accountID)
	if err != nil {
		return map[string]string{}
	}
	names := make(map[string]string, len(policies))
	for _, p := range policies {
		names[p.ID] = p.Name
	}
	return names
}

// policyName resolves a single grant's policy name for a response. Returns ""
// (omitted) when the policy can't be found.
func (h *handler) policyName(ctx context.Context, accountID, policyID string) string {
	p, err := h.jitManager.GetPolicy(ctx, accountID, policyID)
	if err != nil || p == nil {
		return ""
	}
	return p.Name
}

// policyResp builds a policy response, computing source drift for mirror-type
// policies (both false for resource-based). userID is the admin caller, used for
// the permissioned read of the source policy.
//
// TODO: on listPolicies this is one source-policy read per mirror-type policy
// (an N+1 on the admin list). Fine at current volumes; batch the source reads if
// mirror-type policies proliferate.
func (h *handler) policyResp(ctx context.Context, accountID, userID string, p *types.JitPolicy) policyResponse {
	drifted, deleted := h.jitManager.SourceDriftStatus(ctx, accountID, userID, p)
	return toPolicyResponse(p, drifted, deleted)
}

// decodeReason attempts to read an optional {"reason": "..."} body. Errors are
// silently ignored — reason is always optional.
func decodeReason(r *http.Request) string {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	return body.Reason
}
