package types

import "time"

// GrantStatus is the lifecycle status of a JIT grant (request → grant).
type GrantStatus string

const (
	GrantStatusPending    GrantStatus = "pending"
	GrantStatusApproved   GrantStatus = "approved"
	GrantStatusActive     GrantStatus = "active"
	GrantStatusExpired    GrantStatus = "expired"
	GrantStatusDenied     GrantStatus = "denied"
	GrantStatusRevoked    GrantStatus = "revoked"
	GrantStatusCancelled  GrantStatus = "cancelled"
	GrantStatusSuperseded GrantStatus = "superseded"
	GrantStatusFailed     GrantStatus = "failed"
)

// JitTraffic describes the network traffic permitted by a JIT policy.
type JitTraffic struct {
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports,omitempty"`
}

// JitRequestableBy defines who may submit a JIT request for a policy.
// Mode is "all" or "groups"; when Mode=="groups", GroupIDs must be non-empty.
type JitRequestableBy struct {
	Mode     string   `json:"mode"`
	GroupIDs []string `json:"groupIds,omitempty"`
}

// JitApproverCriteria defines who may approve JIT requests for a policy.
// Mode is "any_admin" or "groups"; when Mode=="groups", GroupIDs must be non-empty.
type JitApproverCriteria struct {
	Mode     string   `json:"mode"`
	GroupIDs []string `json:"groupIds,omitempty"`
}

// JitPolicy is a named rule that allows eligible users to request temporary
// access to a set of NetBird resources.
type JitPolicy struct {
	ID          string `gorm:"primaryKey"`
	AccountID   string `gorm:"index"`
	Name        string
	Description string

	// TargetResourceIDs are the NetBird resource IDs this policy gates access to.
	TargetResourceIDs []string `gorm:"serializer:json"`

	// Traffic specifies the protocol/ports allowed on the provisioned policy.
	Traffic JitTraffic `gorm:"serializer:json"`

	MaxDurationMinutes int
	RequestableBy      JitRequestableBy  `gorm:"serializer:json"`
	ApproverCriteria   JitApproverCriteria `gorm:"serializer:json"`
	PendingTTLMinutes  int
	Enabled            bool

	// BackingGroupID is the NetBird group JIT provisions for this policy
	// (empty until provisioned).
	BackingGroupID string
	// NetbirdPolicyID is the NetBird access-policy JIT provisions for this policy
	// (empty until provisioned).
	NetbirdPolicyID string

	// SourcePolicyID is set when this JIT policy mirrors an existing NetBird
	// access-control policy instead of a hand-picked resource list. Empty means
	// the policy is resource-based (custom). The mirror is a one-time snapshot —
	// it is not kept live with the source; re-sync rebuilds it on demand.
	SourcePolicyID string
	// SourcePolicyName is the source policy's name captured at the last sync, so
	// user-facing endpoints (e.g. eligible policies) can show it without a
	// permissioned read of the source policy.
	SourcePolicyName string
	// SourceFingerprint is a hash of the source policy's mirror-relevant content
	// (its enabled rules' destinations/ports/action + posture checks) captured at
	// the last sync. Admin reads compare it against the current source to flag
	// drift ("source changed — re-sync").
	SourceFingerprint string

	CreatedByUserID string
	CreatedByEmail  string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// JitGrant represents a single request→grant lifecycle row.
type JitGrant struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index:idx_jit_grants_account_status_expires,priority:1;index:idx_jit_grants_account_status_pending,priority:1"`
	PolicyID  string `gorm:"index:idx_jit_grants_policy"`

	// SupersedesGrantID links a renewal to the grant it replaces.
	SupersedesGrantID *string

	RequesterUserID          string `gorm:"index:idx_jit_grants_requester_status,priority:1"`
	RequesterEmail           string
	RequestedDurationMinutes int
	Justification            string

	Status GrantStatus `gorm:"index:idx_jit_grants_account_status_expires,priority:2;index:idx_jit_grants_account_status_pending,priority:2;index:idx_jit_grants_requester_status,priority:2"`

	ApproverUserID *string
	ApproverEmail  *string
	DenialReason   *string
	RevokeReason   *string

	RequestedAt      time.Time
	PendingExpiresAt *time.Time `gorm:"index:idx_jit_grants_account_status_pending,priority:3"`
	DecidedAt        *time.Time
	ActivatedAt      *time.Time
	ExpiresAt        *time.Time `gorm:"index:idx_jit_grants_account_status_expires,priority:3"`
	RevokedAt        *time.Time
	LastError        *string
}

// JitGrantPatch carries the optional fields that may be set during a status
// transition. Only non-nil fields are written.
type JitGrantPatch struct {
	ApproverUserID *string
	ApproverEmail  *string
	DenialReason   *string
	RevokeReason   *string
	DecidedAt      *time.Time
	ActivatedAt    *time.Time
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	LastError      *string
}
