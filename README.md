# baton-sql-server
`baton-sql-server` is a connector for Microsoft SQL Server. It communicates with the SQL Server to sync data about users, groups, server roles, databases, and database roles.

It uses [go-mssqldb](https://github.com/microsoft/go-mssqldb) to connect to SQL Server. Check out https://github.com/microsoft/go-mssqldb#connection-parameters-and-dsn for more details on how to connect to your server.

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Getting Started

## Prerequisites

This connector requires that you connect to your SQL Server instance with a user with the proper access to read the system tables. 

### Required Permissions (Read-Only Mode)
- `VIEW ANY DEFINITION` on the server
- `VIEW ANY DATABASE` on the server
- `VIEW ANY DEFINITION` on each database
- `VIEW SERVER STATE` on the server
- `VIEW DATABASE STATE` on each database

### Additional Permissions (Provisioning Mode)
When using provisioning features (`--provisioning` flag), the following additional permissions are required:
- `ALTER ANY LOGIN` - To create and drop server logins
- `ALTER ANY USER` - To create and drop database users
- Permissions to grant/revoke roles and permissions

### Tables Accessed
The following tables are read while syncing data with this connector:
    
- `sys.server_principals`
- `sys.databases`
- `sys.server_permissions`
- `sys.server_role_members`
- `sys.database_principals` on each database
- `sys.database_role_members` on each database

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-sql-server
baton-sql-server --dsn "server=127.0.0.1;user id=sa;password=devP@ssw0rd;port=1433" 
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_DSN="server=127.0.0.1;user id=sa;password=devP@ssw0rd;port=1433" ghcr.io/conductorone/baton-sql-server:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-sql-server/cmd/baton-sql-server@main
baton-sql-server --dsn "server=127.0.0.1;user id=sa;password=devP@ssw0rd;port=1433" 
baton resources
```

# Data Model

`baton-sql-server` syncs information about the following resources:
- Users
- Groups
- Server Roles
- Databases
- Database Roles

When fetching database permissions, the server principal backing the database principal will the resource that is granted entitlements.

# Configuration

## Connection Options

### DSN Connection String
Use the `--dsn` flag (or `BATON_DSN` environment variable) to provide a complete connection string:

```bash
baton-sql-server --dsn "server=127.0.0.1;user id=sa;password=devP@ssw0rd;port=1433"
```

### Windows Integrated Authentication
On Windows systems, you can use integrated authentication by specifying `--db-host` and optionally `--db-port`:

```bash
baton-sql-server --db-host "myserver.local" --db-port 1433
```

If `--db-port` is not provided, it defaults to `1433`. The connector will automatically use Windows integrated authentication.

## Additional Configuration Options

### App Name
Customize the connector display name in metadata:
```bash
--app-name "Production SQL Server"
```
Environment variable: `BATON_APP_NAME`

### Skip Unavailable Databases
Skip databases that are offline, restoring, or otherwise unavailable:
```bash
--skip-unavailable-databases
```
Environment variable: `BATON_SKIP_UNAVAILABLE_DATABASES=true`

### Windows Login Email Domain
Convert Windows login usernames to email format for better user matching in ConductorOne:
```bash
--windows-login-email-domain "example.com"
```
Environment variable: `BATON_WINDOWS_LOGIN_EMAIL_DOMAIN`

This converts Windows logins like `DOMAIN\first.last` to `first.last@example.com`. If not provided, email conversion is disabled.

### Auto-Delete Orphaned Logins
Automatically delete server logins when they lose all meaningful permissions after a revoke operation:
```bash
--auto-delete-orphaned-logins
```
Environment variable: `BATON_AUTO_DELETE_ORPHANED_LOGINS=true`

This feature requires ConductorOne API credentials (see below) to properly remove the user from the app entitlement.

### ConductorOne API Integration
Enable automatic user cleanup by providing ConductorOne API credentials:
```bash
--c1-api-client-id "your-client-id" \
--c1-api-client-secret "your-client-secret" \
--c1-app-id "your-app-id" \
--c1-entitlement-id "app-access-entitlement-id"
```

Environment variables:
- `BATON_C1_API_CLIENT_ID`
- `BATON_C1_API_CLIENT_SECRET`
- `BATON_C1_APP_ID`
- `BATON_C1_ENTITLEMENT_ID`

When all four values are provided, the connector will automatically revoke the user's app entitlement when they lose all meaningful permissions.

## Provisioning Mode

Enable provisioning to allow creating and deleting SQL Server logins through ConductorOne:
```bash
--provisioning
```
Environment variable: `BATON_PROVISIONING=true`

Supported operations:
- **Create Account**: Create SQL Server logins with Windows Authentication, SQL Authentication, Azure AD, or Entra ID
- **Delete Account**: Drop server logins and associated database users
- **Grant/Revoke**: Add or remove users from server roles and database roles

# Development

A docker compose file is included to easily spin up a SQL Server instance for development. To start the instance, run:

```
docker-compose up -d
```

The instance will be available at `localhost:1433`. The default username is `sa` and the default password is `devP@ssw0rd`.

# Contributing, Support, and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-sql-server` Command Line Usage

```
baton-sql-server

Usage:
  baton-sql-server [flags]
  baton-sql-server [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --app-name string                      Custom app name to display in the connector metadata ($BATON_APP_NAME)
      --auto-delete-orphaned-logins          Automatically delete user logins from the server when they have no remaining permissions ($BATON_AUTO_DELETE_ORPHANED_LOGINS)
      --c1-api-client-id string              ConductorOne API client ID for removing user from app entitlement after deletion ($BATON_C1_API_CLIENT_ID)
      --c1-api-client-secret string          ConductorOne API client secret for removing user from app entitlement after deletion ($BATON_C1_API_CLIENT_SECRET)
      --c1-app-id string                     ConductorOne app ID to remove user from entitlement after deletion ($BATON_C1_APP_ID)
      --c1-entitlement-id string             ConductorOne entitlement ID to remove user from after deletion ($BATON_C1_ENTITLEMENT_ID)
      --client-id string                     The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string                 The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --db-host string                       SQL Server hostname or IP address. Used with db-port for Windows integrated authentication ($BATON_DB_HOST)
      --db-port string                       SQL Server port number (default: 1433). Used with db-host for Windows integrated authentication ($BATON_DB_PORT)
      --dsn string                           The connection string for connecting to SQL Server ($BATON_DSN)
  -f, --file string                          The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                                 help for baton-sql-server
      --log-format string                    The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                     The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                         This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync                       This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --skip-unavailable-databases           Skip databases that are unavailable (offline, restoring, etc) ($BATON_SKIP_UNAVAILABLE_DATABASES)
      --ticketing                            This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                              version for baton-sql-server
      --windows-login-email-domain string    Email domain to use when converting Windows login usernames to email format ($BATON_WINDOWS_LOGIN_EMAIL_DOMAIN)

Use "baton-sql-server [command] --help" for more information about a command.
```
