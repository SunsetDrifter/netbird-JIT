package jit

import (
	"time"

	"github.com/netbirdio/netbird/management/server/jit"
	"github.com/netbirdio/netbird/management/server/types"
)

// ---------------------------------------------------------------------------
// Request body structs (decoded from JSON; mirror OpenAPI request schemas)
// ---------------------------------------------------------------------------

type trafficBody struct {
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports,omitempty"`
}

type requestableByBody struct {
	Mode     string   `json:"mode"`
	GroupIds []string `json:"groupIds,omitempty"`
}

type approverCriteriaBody struct {
	Mode     string   `json:"mode"`
	GroupIds []string `json:"groupIds,omitempty"`
}

type createPolicyRequest struct {
	Name               string               `json:"name"`
	Description        string               `json:"description"`
	TargetResourceIds  []string             `json:"targetResourceIds"`
	Traffic            *trafficBody         `json:"traffic,omitempty"`
	MaxDurationMinutes int                  `json:"maxDurationMinutes"`
	RequestableBy      requestableByBody    `json:"requestableBy"`
	ApproverCriteria   approverCriteriaBody `json:"approverCriteria"`
	PendingTtlMinutes  *int                 `json:"pendingTtlMinutes,omitempty"`
}

type updatePolicyRequest struct {
	Name               *string               `json:"name,omitempty"`
	Description        *string               `json:"description,omitempty"`
	TargetResourceIds  *[]string             `json:"targetResourceIds,omitempty"`
	Traffic            *trafficBody          `json:"traffic,omitempty"`
	MaxDurationMinutes *int                  `json:"maxDurationMinutes,omitempty"`
	RequestableBy      *requestableByBody    `json:"requestableBy,omitempty"`
	ApproverCriteria   *approverCriteriaBody `json:"approverCriteria,omitempty"`
	PendingTtlMinutes  *int                  `json:"pendingTtlMinutes,omitempty"`
	Enabled            *bool                 `json:"enabled,omitempty"`
}

type createRequestBody struct {
	PolicyId        string `json:"policyId"`
	DurationMinutes int    `json:"durationMinutes"`
	Justification   string `json:"justification,omitempty"`
}

type extendBody struct {
	DurationMinutes int `json:"durationMinutes"`
}

// ---------------------------------------------------------------------------
// Response structs (written as JSON; mirror OpenAPI response schemas)
// ---------------------------------------------------------------------------

type trafficResponse struct {
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports,omitempty"`
}

type requestableByResponse struct {
	Mode     string   `json:"mode"`
	GroupIds []string `json:"groupIds,omitempty"`
}

type approverCriteriaResponse struct {
	Mode     string   `json:"mode"`
	GroupIds []string `json:"groupIds,omitempty"`
}

type policyResponse struct {
	ID                 string                   `json:"id"`
	Name               string                   `json:"name"`
	Description        string                   `json:"description,omitempty"`
	TargetResourceIds  []string                 `json:"targetResourceIds"`
	Traffic            trafficResponse          `json:"traffic"`
	MaxDurationMinutes int                      `json:"maxDurationMinutes"`
	RequestableBy      requestableByResponse    `json:"requestableBy"`
	ApproverCriteria   approverCriteriaResponse `json:"approverCriteria"`
	PendingTtlMinutes  int                      `json:"pendingTtlMinutes"`
	Enabled            bool                     `json:"enabled"`
	BackingGroupId     *string                  `json:"backingGroupId"`
	NetbirdPolicyId    *string                  `json:"netbirdPolicyId"`
	CreatedByUserId    string                   `json:"createdByUserId"`
	CreatedByEmail     string                   `json:"createdByEmail,omitempty"`
	CreatedAt          string                   `json:"createdAt"`
	UpdatedAt          string                   `json:"updatedAt"`
}

type eligiblePolicyResponse struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Description        string   `json:"description,omitempty"`
	TargetResourceIds  []string `json:"targetResourceIds"`
	MaxDurationMinutes int      `json:"maxDurationMinutes"`
}

type grantResponse struct {
	ID                       string  `json:"id"`
	PolicyId                 string  `json:"policyId"`
	PolicyName               string  `json:"policyName,omitempty"`
	SupersedesGrantId        *string `json:"supersedesGrantId,omitempty"`
	RequesterUserId          string  `json:"requesterUserId"`
	RequesterEmail           string  `json:"requesterEmail,omitempty"`
	RequestedDurationMinutes int     `json:"requestedDurationMinutes"`
	Justification            string  `json:"justification,omitempty"`
	Status                   string  `json:"status"`
	ApproverUserId           *string `json:"approverUserId,omitempty"`
	ApproverEmail            *string `json:"approverEmail,omitempty"`
	DenialReason             *string `json:"denialReason,omitempty"`
	RevokeReason             *string `json:"revokeReason,omitempty"`
	RequestedAt              string  `json:"requestedAt"`
	PendingExpiresAt         *string `json:"pendingExpiresAt,omitempty"`
	DecidedAt                *string `json:"decidedAt,omitempty"`
	ActivatedAt              *string `json:"activatedAt,omitempty"`
	ExpiresAt                *string `json:"expiresAt,omitempty"`
	RevokedAt                *string `json:"revokedAt,omitempty"`
	LastError                *string `json:"lastError,omitempty"`
}

// ---------------------------------------------------------------------------
// Conversion: request bodies → domain inputs
// ---------------------------------------------------------------------------

func toTraffic(b trafficBody) types.JitTraffic {
	return types.JitTraffic{Protocol: b.Protocol, Ports: b.Ports}
}

func toRequestableBy(b requestableByBody) types.JitRequestableBy {
	return types.JitRequestableBy{Mode: b.Mode, GroupIDs: b.GroupIds}
}

func toApproverCriteria(b approverCriteriaBody) types.JitApproverCriteria {
	return types.JitApproverCriteria{Mode: b.Mode, GroupIDs: b.GroupIds}
}

func toPatch(req updatePolicyRequest) jit.UpdateJitPolicyInput {
	patch := jit.UpdateJitPolicyInput{
		Name:               req.Name,
		Description:        req.Description,
		TargetResourceIDs:  req.TargetResourceIds,
		MaxDurationMinutes: req.MaxDurationMinutes,
		PendingTTLMinutes:  req.PendingTtlMinutes,
		Enabled:            req.Enabled,
	}
	if req.Traffic != nil {
		t := toTraffic(*req.Traffic)
		patch.Traffic = &t
	}
	if req.RequestableBy != nil {
		rb := toRequestableBy(*req.RequestableBy)
		patch.RequestableBy = &rb
	}
	if req.ApproverCriteria != nil {
		ac := toApproverCriteria(*req.ApproverCriteria)
		patch.ApproverCriteria = &ac
	}
	return patch
}

// ---------------------------------------------------------------------------
// Conversion: domain types → response structs
// ---------------------------------------------------------------------------

func toPolicyResponse(p *types.JitPolicy) policyResponse {
	resp := policyResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		TargetResourceIds: func() []string {
			if p.TargetResourceIDs == nil {
				return []string{}
			}
			return p.TargetResourceIDs
		}(),
		Traffic:            trafficResponse{Protocol: p.Traffic.Protocol, Ports: p.Traffic.Ports},
		MaxDurationMinutes: p.MaxDurationMinutes,
		RequestableBy:      requestableByResponse{Mode: p.RequestableBy.Mode, GroupIds: p.RequestableBy.GroupIDs},
		ApproverCriteria:   approverCriteriaResponse{Mode: p.ApproverCriteria.Mode, GroupIds: p.ApproverCriteria.GroupIDs},
		PendingTtlMinutes:  p.PendingTTLMinutes,
		Enabled:            p.Enabled,
		CreatedByUserId:    p.CreatedByUserID,
		CreatedByEmail:     p.CreatedByEmail,
		CreatedAt:          p.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:          p.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if p.BackingGroupID != "" {
		resp.BackingGroupId = &p.BackingGroupID
	}
	if p.NetbirdPolicyID != "" {
		resp.NetbirdPolicyId = &p.NetbirdPolicyID
	}
	return resp
}

func toEligiblePolicyResponse(p *types.JitPolicy) eligiblePolicyResponse {
	return eligiblePolicyResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		TargetResourceIds: func() []string {
			if p.TargetResourceIDs == nil {
				return []string{}
			}
			return p.TargetResourceIDs
		}(),
		MaxDurationMinutes: p.MaxDurationMinutes,
	}
}

func toGrantResponse(g *types.JitGrant, policyName string) grantResponse {
	resp := grantResponse{
		ID:                       g.ID,
		PolicyId:                 g.PolicyID,
		PolicyName:               policyName,
		SupersedesGrantId:        g.SupersedesGrantID,
		RequesterUserId:          g.RequesterUserID,
		RequesterEmail:           g.RequesterEmail,
		RequestedDurationMinutes: g.RequestedDurationMinutes,
		Justification:            g.Justification,
		Status:                   string(g.Status),
		ApproverUserId:           g.ApproverUserID,
		ApproverEmail:            g.ApproverEmail,
		DenialReason:             g.DenialReason,
		RevokeReason:             g.RevokeReason,
		RequestedAt:              g.RequestedAt.UTC().Format(time.RFC3339),
		LastError:                g.LastError,
	}
	if g.PendingExpiresAt != nil {
		s := g.PendingExpiresAt.UTC().Format(time.RFC3339)
		resp.PendingExpiresAt = &s
	}
	if g.DecidedAt != nil {
		s := g.DecidedAt.UTC().Format(time.RFC3339)
		resp.DecidedAt = &s
	}
	if g.ActivatedAt != nil {
		s := g.ActivatedAt.UTC().Format(time.RFC3339)
		resp.ActivatedAt = &s
	}
	if g.ExpiresAt != nil {
		s := g.ExpiresAt.UTC().Format(time.RFC3339)
		resp.ExpiresAt = &s
	}
	if g.RevokedAt != nil {
		s := g.RevokedAt.UTC().Format(time.RFC3339)
		resp.RevokedAt = &s
	}
	return resp
}
