package jit

import (
	"github.com/netbirdio/netbird/management/server/types"
)

// Caller is the authenticated identity performing a grant operation. It is the
// Go port of the sidecar's auth.Caller. Role is resolved upstream (Task 9, from
// NetBird — never from the JWT); the grant service consumes only the derived
// IsAdmin flag plus the caller's group membership for eligibility/approver
// intersection checks.
type Caller struct {
	// UserID is the NetBird user ID of the caller.
	UserID string
	// Email is the caller's email, stamped onto audit/approver fields.
	Email string
	// IsAdmin is true when the caller has the admin or owner role.
	IsAdmin bool
	// Groups are the caller's auto_groups, used for eligibility and
	// approver-criteria group intersections.
	Groups []string
}

// hasGroupIntersection reports whether a and b share at least one element.
func hasGroupIntersection(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, g := range a {
		set[g] = struct{}{}
	}
	for _, g := range b {
		if _, ok := set[g]; ok {
			return true
		}
	}
	return false
}

// IsEligible reports whether the caller may request the given JIT policy.
// Mode "all" admits everyone; otherwise the caller must belong to at least one
// of the policy's requestable-by groups. Ported verbatim from guards.ts.
func IsEligible(caller Caller, rb types.JitRequestableBy) bool {
	if rb.Mode == "all" {
		return true
	}
	return hasGroupIntersection(caller.Groups, rb.GroupIDs)
}

// CanApprove reports whether the caller may approve/deny Requests for the given
// JIT policy. Admins (and owners) may always approve; otherwise, when the
// criteria is group-based, the caller must belong to at least one approver
// group. Ported verbatim from guards.ts.
func CanApprove(caller Caller, ac types.JitApproverCriteria) bool {
	if caller.IsAdmin {
		return true
	}
	return ac.Mode == "groups" && hasGroupIntersection(caller.Groups, ac.GroupIDs)
}
