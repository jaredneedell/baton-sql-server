package mssqldb

import "strings"

// IgnoredPermissionsForDeletion contains permission codes that should be ignored
// when checking if a user has remaining permissions for auto-deletion purposes.
// These are basic connection permissions that don't represent meaningful access.
var IgnoredPermissionsForDeletion = struct {
	Server   []string
	Database []string
}{
	Server:   []string{"COSQ", "CADB"}, // Connect SQL, Connect Any Database
	Database: []string{"CO"},           // Connect
}

// BuildIgnoredPermissionsClause builds a SQL clause to exclude ignored permissions.
// Returns an empty string if no permissions are provided.
func BuildIgnoredPermissionsClause(permissions []string) string {
	if len(permissions) == 0 {
		return ""
	}
	if len(permissions) == 1 {
		return "AND type != '" + permissions[0] + "'"
	}
	// Build NOT IN clause for multiple permissions
	quoted := make([]string, len(permissions))
	for i, perm := range permissions {
		quoted[i] = "'" + perm + "'"
	}
	return "AND type NOT IN (" + strings.Join(quoted, ", ") + ")"
}

