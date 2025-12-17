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
	c1ApiClientId = field.StringField("c1-api-client-id",
		field.WithDescription("ConductorOne API client ID for removing user from app entitlement after deletion. Optional - if not provided, entitlement removal will not be performed."))
	c1ApiClientSecret = field.StringField("c1-api-client-secret",
		field.WithDescription("ConductorOne API client secret for removing user from app entitlement after deletion. Optional - if not provided, entitlement removal will not be performed."))
	c1AppId = field.StringField("c1-app-id",
		field.WithDescription("ConductorOne app ID to remove user from entitlement after deletion. Optional - if not provided, entitlement removal will not be performed."))
	c1EntitlementId = field.StringField("c1-entitlement-id",
		field.WithDescription("ConductorOne entitlement ID (typically 'App Access') to remove user from after deletion. Optional - if not provided, entitlement removal will not be performed."))
)

var cfg = field.Configuration{
	Fields: []field.SchemaField{dsn, skipUnavailableDatabases, appName, autoDeleteOrphanedLogins, windowsLoginEmailDomain, c1ApiClientId, c1ApiClientSecret, c1AppId, c1EntitlementId},
}
