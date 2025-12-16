package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	dsn = field.StringField("dsn",
		field.WithDescription("The connection string for connecting to SQL Server"),
		field.WithRequired(true))
	skipUnavailableDatabases = field.BoolField("skip-unavailable-databases",
		field.WithDescription("Skip databases that are unavailable (offline, restoring, etc)"))
	appName = field.StringField("app-name",
		field.WithDescription("Custom app name to display in the connector metadata. If not set, defaults to 'Microsoft SQL Server ({serverName})'"))
	autoDeleteOrphanedLogins = field.BoolField("auto-delete-orphaned-logins",
		field.WithDescription("Automatically delete user logins from the server when they have no remaining permissions after a revoke operation"))
	windowsLoginEmailDomain = field.StringField("windows-login-email-domain",
		field.WithDescription("Email domain to use when converting Windows login usernames to email format (e.g., 'rithum.com'). Defaults to 'rithum.com'"))
)

var cfg = field.Configuration{
	Fields: []field.SchemaField{dsn, skipUnavailableDatabases, appName, autoDeleteOrphanedLogins, windowsLoginEmailDomain},
}
