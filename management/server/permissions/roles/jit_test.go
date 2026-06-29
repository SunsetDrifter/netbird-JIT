package roles_test

import (
	"testing"

	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
)

// resolvePermission mirrors managerImpl.ValidateRoleModuleAccess logic:
// explicit Permissions entry wins; otherwise fall back to AutoAllowNew.
func resolvePermission(role roles.RolePermissions, module modules.Module, op operations.Operation) bool {
	if permissions, ok := role.Permissions[module]; ok {
		if allowed, exists := permissions[op]; exists {
			return allowed
		}
		return false
	}
	return role.AutoAllowNew[op]
}

func TestJitModulePermissions_Owner(t *testing.T) {
	t.Parallel()

	role := roles.RolesMap[types.UserRoleOwner]

	for _, op := range []operations.Operation{
		operations.Create, operations.Read, operations.Update, operations.Delete,
	} {
		if !resolvePermission(role, modules.Jit, op) {
			t.Errorf("Owner: expected modules.Jit %s to be allowed", op)
		}
	}
}

func TestJitModulePermissions_Admin(t *testing.T) {
	t.Parallel()

	role := roles.RolesMap[types.UserRoleAdmin]

	for _, op := range []operations.Operation{
		operations.Create, operations.Read, operations.Update, operations.Delete,
	} {
		if !resolvePermission(role, modules.Jit, op) {
			t.Errorf("Admin: expected modules.Jit %s to be allowed", op)
		}
	}
}

func TestJitModulePermissions_Auditor(t *testing.T) {
	t.Parallel()

	role := roles.RolesMap[types.UserRoleAuditor]

	if !resolvePermission(role, modules.Jit, operations.Read) {
		t.Error("Auditor: expected modules.Jit Read to be allowed")
	}

	for _, op := range []operations.Operation{
		operations.Create, operations.Update, operations.Delete,
	} {
		if resolvePermission(role, modules.Jit, op) {
			t.Errorf("Auditor: expected modules.Jit %s to be denied", op)
		}
	}
}

func TestJitModulePermissions_User(t *testing.T) {
	t.Parallel()

	role := roles.RolesMap[types.UserRoleUser]

	for _, op := range []operations.Operation{
		operations.Create, operations.Read, operations.Update, operations.Delete,
	} {
		if resolvePermission(role, modules.Jit, op) {
			t.Errorf("User: expected modules.Jit %s to be denied", op)
		}
	}
}

func TestJitModulePermissions_NetworkAdmin(t *testing.T) {
	t.Parallel()

	role := roles.RolesMap[types.UserRoleNetworkAdmin]

	for _, op := range []operations.Operation{
		operations.Create, operations.Read, operations.Update, operations.Delete,
	} {
		if resolvePermission(role, modules.Jit, op) {
			t.Errorf("NetworkAdmin: expected modules.Jit %s to be denied", op)
		}
	}
}

func TestJitModuleInAll(t *testing.T) {
	t.Parallel()

	if _, ok := modules.All[modules.Jit]; !ok {
		t.Error("modules.Jit is not present in modules.All")
	}
}
