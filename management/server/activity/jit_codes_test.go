package activity_test

import (
	"testing"

	"github.com/netbirdio/netbird/management/server/activity"
)

func TestJitActivityCodes_NonEmpty(t *testing.T) {
	t.Parallel()

	jitCodes := []activity.Activity{
		activity.JitPolicyCreated,
		activity.JitPolicyUpdated,
		activity.JitPolicyDeleted,
		activity.JitAccessRequested,
		activity.JitAccessApproved,
		activity.JitAccessDenied,
		activity.JitAccessCancelled,
		activity.JitAccessRevoked,
		activity.JitAccessExpired,
		activity.JitAccessExtended,
	}

	for _, code := range jitCodes {
		msg := code.Message()
		if msg == "" || msg == "UNKNOWN_ACTIVITY" {
			t.Errorf("activity %d: expected non-empty message, got %q", code, msg)
		}

		strCode := code.StringCode()
		if strCode == "" || strCode == "UNKNOWN_ACTIVITY" {
			t.Errorf("activity %d: expected non-empty string code, got %q", code, strCode)
		}
	}
}

func TestJitActivityCodes_UniqueValues(t *testing.T) {
	t.Parallel()

	jitCodes := []activity.Activity{
		activity.JitPolicyCreated,
		activity.JitPolicyUpdated,
		activity.JitPolicyDeleted,
		activity.JitAccessRequested,
		activity.JitAccessApproved,
		activity.JitAccessDenied,
		activity.JitAccessCancelled,
		activity.JitAccessRevoked,
		activity.JitAccessExpired,
		activity.JitAccessExtended,
	}

	seen := make(map[activity.Activity]bool)
	for _, code := range jitCodes {
		if seen[code] {
			t.Errorf("duplicate activity code value %d", code)
		}
		seen[code] = true
	}
}
