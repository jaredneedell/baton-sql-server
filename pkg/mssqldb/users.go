package mssqldb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

const (
	UserType         = "user"
	DatabaseUserType = "database-user"
)

var ErrNoServerPrincipal = errors.New("no server principal found")

type UserModel struct {
	ID         string `db:"principal_id"`
	SecurityID string `db:"sid"`
	Name       string `db:"name"`
	Type       string `db:"type_desc"`
	IsDisabled bool   `db:"is_disabled"`
}

type UserDBModel struct {
	ID                  string         `db:"principal_id"`
	DatabasePrincipalId sql.NullString `db:"database_principal_id"`
	Sid                 string         `db:"sid"`
	Name                string         `db:"name"`
	Type                string         `db:"type_desc"`
	CreateDate          string         `db:"create_date"`
	ModifyDate          string         `db:"modify_date"`
	OwningPrincipalId   sql.NullString `db:"owning_principal_id"`
}

func (c *Client) ListServerUserPrincipals(ctx context.Context, pager *Pager) ([]*UserModel, string, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("listing user principals")

	offset, limit, err := pager.Parse()
	if err != nil {
		return nil, "", err
	}
	args := []interface{}{offset, limit + 1}

	var sb strings.Builder
	// Fetch the user principals.
	// https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql
	_, _ = sb.WriteString(`
SELECT 
  principal_id,
  sid,
  name, 
  type_desc,
  is_disabled
FROM 
  sys.server_principals
WHERE 
  (
    type = 'S' 
    OR type = 'U' 
    OR type = 'C' 
    OR type = 'E' 
    OR type = 'K'
    OR type = 'G'
    OR type = 'X'
  ) 
ORDER BY 
  principal_id ASC OFFSET @p1 ROWS FETCH NEXT @p2 ROWS ONLY
`)

	rows, err := c.db.QueryxContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var ret []*UserModel
	for rows.Next() {
		var userModel UserModel
		err = rows.StructScan(&userModel)
		if err != nil {
			return nil, "", err
		}
		ret = append(ret, &userModel)
	}
	if rows.Err() != nil {
		return nil, "", rows.Err()
	}

	var nextPageToken string
	if len(ret) > limit {
		offset += limit
		nextPageToken = strconv.Itoa(offset)
		ret = ret[:limit]
	}

	return ret, nextPageToken, nil
}

// GetServerPrincipalForDatabasePrincipal returns the server principal for a given database user.
// Returns ErrNoServerPrincipal if no server principal is found.
func (c *Client) GetServerPrincipalForDatabasePrincipal(ctx context.Context, dbName string, principalID int64) (*UserModel, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting server principal for database user")

	var sb strings.Builder
	_, _ = sb.WriteString(`
SELECT
	principal_id,
	sid,
	name,
	type_desc,
	is_disabled
FROM
    sys.server_principals 
WHERE sid = (SELECT sid FROM [`)
	_, _ = sb.WriteString(dbName)
	_, _ = sb.WriteString(`].sys.database_principals WHERE principal_id = @p1)`)

	row := c.db.QueryRowxContext(ctx, sb.String(), principalID)
	if row.Err() != nil {
		return nil, row.Err()
	}

	var ret UserModel
	err := row.StructScan(&ret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoServerPrincipal
		}
		return nil, err
	}

	return &ret, nil
}

func (c *Client) ListDatabaseUserPrincipals(ctx context.Context, dbName string, pager *Pager) ([]*UserModel, string, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("listing database user principals")

	offset, limit, err := pager.Parse()
	if err != nil {
		return nil, "", err
	}
	args := []interface{}{offset, limit + 1}

	var sb strings.Builder
	_, _ = sb.WriteString(`
SELECT 
  principal_id,
  name, 
  type_desc
FROM [`)
	_, _ = sb.WriteString(dbName)
	_, _ = sb.WriteString(`].sys.database_principals
WHERE 
  (
    type = 'S' 
    OR type = 'U' 
    OR type = 'C' 
    OR type = 'E' 
    OR type = 'K'
    OR type = 'G'
    OR type = 'X'
  ) 
ORDER BY 
  principal_id ASC OFFSET @p1 ROWS FETCH NEXT @p2 ROWS ONLY
`)

	rows, err := c.db.QueryxContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var ret []*UserModel
	for rows.Next() {
		var userModel UserModel
		err = rows.StructScan(&userModel)
		if err != nil {
			return nil, "", err
		}
		ret = append(ret, &userModel)
	}
	if rows.Err() != nil {
		return nil, "", rows.Err()
	}

	var nextPageToken string
	if len(ret) > limit {
		offset += limit
		nextPageToken = strconv.Itoa(offset)
		ret = ret[:limit]
	}

	return ret, nextPageToken, nil
}

func (c *Client) GetUserPrincipal(ctx context.Context, userId string) (*UserModel, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting user")

	query := `
SELECT
    principal_id,
    sid,
    name,
    type_desc,
    is_disabled
FROM
    sys.server_principals
WHERE
    (
		type = 'S'
		OR type = 'U'
		OR type = 'C'
		OR type = 'E'
		OR type = 'K'
		OR type = 'G'
		OR type = 'X'
	) AND principal_id = @p1
`

	rows := c.db.QueryRowxContext(ctx, query, userId)
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var userModel UserModel
	err := rows.StructScan(&userModel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %s", userId)
		}
		return nil, err
	}

	return &userModel, nil
}

func (c *Client) GetUserPrincipalByName(ctx context.Context, name string) (*UserModel, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting user")

	query := `
SELECT
    principal_id,
    sid,
    name,
    type_desc,
    is_disabled
FROM
    sys.server_principals
WHERE
    (
		type = 'S'
		OR type = 'U'
		OR type = 'C'
		OR type = 'E'
		OR type = 'K'
		OR type = 'G'
		OR type = 'X'
	) AND name = @p1
`

	rows := c.db.QueryRowxContext(ctx, query, name)
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var userModel UserModel
	err := rows.StructScan(&userModel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user name not found: %s", name)
		}
		return nil, err
	}

	return &userModel, nil
}

// GetUserFromDb find db user from Server principal.
func (c *Client) GetUserFromDb(ctx context.Context, db, principalId string) (*UserDBModel, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting user")

	if strings.ContainsAny(db, "[]\"';") {
		return nil, fmt.Errorf("invalid characters in dbName")
	}

	query := `
USE [%s];
SELECT
    dp.principal_id AS principal_id,
    sp.principal_id AS database_principal_id,
	dp.sid AS sid,
	dp.name as name,
	dp.type_desc AS type_desc,
	dp.create_date AS create_date,
	dp.modify_date AS modify_date,
	dp.owning_principal_id as owning_principal_id
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp
ON dp.sid = sp.sid
WHERE dp.type IN ('S', 'U')
AND dp.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys')
AND sp.principal_id = @p1
`

	query = fmt.Sprintf(query, db)

	row := c.db.QueryRowxContext(ctx, query, principalId)
	if err := row.Err(); err != nil {
		return nil, err
	}

	var userModel UserDBModel
	err := row.StructScan(&userModel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			l.Info("user not found for principal", zap.String("principalId", principalId))
			return nil, nil
		}
		return nil, err
	}

	return &userModel, nil
}

func (c *Client) CreateDatabaseUserForPrincipal(ctx context.Context, db, principal string) error {
	l := ctxzap.Extract(ctx)
	l.Debug("creating user for db user", zap.String("db", db), zap.String("principal", principal))

	if strings.ContainsAny(db, "[]\"';") || strings.ContainsAny(principal, "[]\"';") {
		return fmt.Errorf("invalid characters in dbName or principal")
	}

	query := `
USE [%s];
CREATE USER [%s] FOR LOGIN [%s];
`

	query = fmt.Sprintf(query, db, principal, principal)

	l.Debug("SQL QUERY", zap.String("q", query))

	_, err := c.db.ExecContext(ctx, query)

	if err != nil {
		return err
	}

	return nil
}

// UserHasRemainingPermissions checks if a user has any remaining permissions, roles, or grants.
// Returns true if the user has any permissions, false otherwise.
func (c *Client) UserHasRemainingPermissions(ctx context.Context, principalID string) (bool, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("checking if user has remaining permissions", zap.String("principal_id", principalID))

	// Check server-level permissions (excluding ignored permissions)
	var serverPermCount int
	query := `
	SELECT COUNT(*) 
	FROM sys.server_permissions 
	WHERE grantee_principal_id = @p1 
	AND (state = 'G' OR state = 'W')
	` + BuildIgnoredPermissionsClause(IgnoredPermissionsForDeletion.Server)
	err := c.db.GetContext(ctx, &serverPermCount, query, principalID)
	if err != nil {
		return false, fmt.Errorf("failed to check server permissions: %w", err)
	}
	if serverPermCount > 0 {
		l.Debug("user has server permissions", zap.Int("count", serverPermCount))
		return true, nil
	}

	// Check server role memberships
	var serverRoleCount int
	query = `
	SELECT COUNT(*) 
	FROM sys.server_role_members 
	WHERE member_principal_id = @p1
	`
	err = c.db.GetContext(ctx, &serverRoleCount, query, principalID)
	if err != nil {
		return false, fmt.Errorf("failed to check server role memberships: %w", err)
	}
	if serverRoleCount > 0 {
		l.Debug("user has server role memberships", zap.Int("count", serverRoleCount))
		return true, nil
	}

	// Check database-level permissions and role memberships across all databases
	// Get list of all databases
	databases, _, err := c.ListDatabases(ctx, &Pager{Size: 1000})
	if err != nil {
		return false, fmt.Errorf("failed to list databases: %w", err)
	}

	for _, db := range databases {
		if c.skipUnavailableDatabases && db.StateDesc != "ONLINE" {
			continue
		}

		// Check if user exists in this database
		var dbPrincipalID int64
		query = fmt.Sprintf(`
		SELECT principal_id 
		FROM [%s].sys.database_principals 
		WHERE sid = (SELECT sid FROM sys.server_principals WHERE principal_id = @p1)
		AND type IN ('S', 'U', 'C', 'E', 'K')
		`, db.Name)
		err = c.db.GetContext(ctx, &dbPrincipalID, query, principalID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			l.Warn("error checking database principal", zap.String("database", db.Name), zap.Error(err))
			continue
		}

		// Check database-level permissions (excluding ignored permissions)
		var dbPermCount int
		query = fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM [%s].sys.database_permissions 
		WHERE grantee_principal_id = @p1 
		AND (state = 'G' OR state = 'W')
		%s
		`, db.Name, BuildIgnoredPermissionsClause(IgnoredPermissionsForDeletion.Database))
		err = c.db.GetContext(ctx, &dbPermCount, query, dbPrincipalID)
		if err != nil {
			l.Warn("error checking database permissions", zap.String("database", db.Name), zap.Error(err))
			continue
		}
		if dbPermCount > 0 {
			l.Debug("user has database permissions", zap.String("database", db.Name), zap.Int("count", dbPermCount))
			return true, nil
		}

		// Check database role memberships
		var dbRoleCount int
		query = fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM [%s].sys.database_role_members 
		WHERE member_principal_id = @p1
		`, db.Name)
		err = c.db.GetContext(ctx, &dbRoleCount, query, dbPrincipalID)
		if err != nil {
			l.Warn("error checking database role memberships", zap.String("database", db.Name), zap.Error(err))
			continue
		}
		if dbRoleCount > 0 {
			l.Debug("user has database role memberships", zap.String("database", db.Name), zap.Int("count", dbRoleCount))
			return true, nil
		}
	}

	l.Debug("user has no remaining permissions", zap.String("principal_id", principalID))
	return false, nil
}

// UserHasRemainingServerPermissions checks if a user has any remaining server-level permissions or roles.
// Returns true if the user has any server-level permissions, false otherwise.
func (c *Client) UserHasRemainingServerPermissions(ctx context.Context, principalID string) (bool, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("checking if user has remaining server permissions", zap.String("principal_id", principalID))

	// Check server-level permissions (excluding ignored permissions)
	var serverPermCount int
	query := `
	SELECT COUNT(*) 
	FROM sys.server_permissions 
	WHERE grantee_principal_id = @p1 
	AND (state = 'G' OR state = 'W')
	` + BuildIgnoredPermissionsClause(IgnoredPermissionsForDeletion.Server)
	err := c.db.GetContext(ctx, &serverPermCount, query, principalID)
	if err != nil {
		return false, fmt.Errorf("failed to check server permissions: %w", err)
	}
	if serverPermCount > 0 {
		l.Debug("user has server permissions", zap.Int("count", serverPermCount))
		return true, nil
	}

	// Check server role memberships
	var serverRoleCount int
	query = `
	SELECT COUNT(*) 
	FROM sys.server_role_members 
	WHERE member_principal_id = @p1
	`
	err = c.db.GetContext(ctx, &serverRoleCount, query, principalID)
	if err != nil {
		return false, fmt.Errorf("failed to check server role memberships: %w", err)
	}
	if serverRoleCount > 0 {
		l.Debug("user has server role memberships", zap.Int("count", serverRoleCount))
		return true, nil
	}

	l.Debug("user has no remaining server permissions", zap.String("principal_id", principalID))
	return false, nil
}

// UserHasRemainingDatabasePermissions checks if a user has any remaining permissions or roles in a specific database.
// Returns true if the user has any database-level permissions, false otherwise.
func (c *Client) UserHasRemainingDatabasePermissions(ctx context.Context, principalID string, dbName string) (bool, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("checking if user has remaining database permissions", zap.String("principal_id", principalID), zap.String("database", dbName))

	if strings.ContainsAny(dbName, "[]\"';") {
		return false, fmt.Errorf("invalid characters in dbName")
	}

	// Check if user exists in this database
	var dbPrincipalID int64
	query := fmt.Sprintf(`
	SELECT principal_id 
	FROM [%s].sys.database_principals 
	WHERE sid = (SELECT sid FROM sys.server_principals WHERE principal_id = @p1)
	AND type IN ('S', 'U', 'C', 'E', 'K')
	`, dbName)
	err := c.db.GetContext(ctx, &dbPrincipalID, query, principalID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// User doesn't exist in this database, so no permissions
			return false, nil
		}
		return false, fmt.Errorf("failed to check database principal: %w", err)
	}

	// Check database-level permissions (excluding ignored permissions)
	var dbPermCount int
	query = fmt.Sprintf(`
	SELECT COUNT(*) 
	FROM [%s].sys.database_permissions 
	WHERE grantee_principal_id = @p1 
	AND (state = 'G' OR state = 'W')
	AND class = 0 AND major_id = 0
	%s
	`, dbName, BuildIgnoredPermissionsClause(IgnoredPermissionsForDeletion.Database))
	err = c.db.GetContext(ctx, &dbPermCount, query, dbPrincipalID)
	if err != nil {
		return false, fmt.Errorf("failed to check database permissions: %w", err)
	}
	if dbPermCount > 0 {
		l.Debug("user has database permissions", zap.String("database", dbName), zap.Int("count", dbPermCount))
		return true, nil
	}

	// Check database role memberships
	var dbRoleCount int
	query = fmt.Sprintf(`
	SELECT COUNT(*) 
	FROM [%s].sys.database_role_members 
	WHERE member_principal_id = @p1
	`, dbName)
	err = c.db.GetContext(ctx, &dbRoleCount, query, dbPrincipalID)
	if err != nil {
		return false, fmt.Errorf("failed to check database role memberships: %w", err)
	}
	if dbRoleCount > 0 {
		l.Debug("user has database role memberships", zap.String("database", dbName), zap.Int("count", dbRoleCount))
		return true, nil
	}

	l.Debug("user has no remaining database permissions", zap.String("principal_id", principalID), zap.String("database", dbName))
	return false, nil
}

// DatabaseUserInfo contains information about a database user
type DatabaseUserInfo struct {
	DatabaseName string
	UserName     string
}

// FindAllDatabaseUsersForServerPrincipal finds all databases where a server principal exists as a database user.
// Returns a list of database name and database user name pairs.
func (c *Client) FindAllDatabaseUsersForServerPrincipal(ctx context.Context, serverPrincipalID string) ([]DatabaseUserInfo, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("finding all database users for server principal", zap.String("principal_id", serverPrincipalID))

	// Get list of all databases
	databases, _, err := c.ListDatabases(ctx, &Pager{Size: 1000})
	if err != nil {
		return nil, fmt.Errorf("failed to list databases: %w", err)
	}

	var dbUsers []DatabaseUserInfo
	for _, db := range databases {
		if c.skipUnavailableDatabases && db.StateDesc != "ONLINE" {
			continue
		}

		// Check if user exists in this database and get the database user name
		var dbUserName string
		query := fmt.Sprintf(`
		SELECT name 
		FROM [%s].sys.database_principals 
		WHERE sid = (SELECT sid FROM sys.server_principals WHERE principal_id = @p1)
		AND type IN ('S', 'U', 'C', 'E', 'K')
		`, db.Name)
		err = c.db.GetContext(ctx, &dbUserName, query, serverPrincipalID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// User doesn't exist in this database, skip
				continue
			}
			l.Warn("error checking database user", zap.String("database", db.Name), zap.Error(err))
			continue
		}

		// User exists in this database
		dbUsers = append(dbUsers, DatabaseUserInfo{
			DatabaseName: db.Name,
			UserName:     dbUserName,
		})
	}

	return dbUsers, nil
}

// DeleteUserFromDatabase deletes a user from a specific database.
func (c *Client) DeleteUserFromDatabase(ctx context.Context, dbName string, userName string) error {
	if strings.ContainsAny(dbName, "[]\"';") || strings.ContainsAny(userName, "[]\"';") {
		return fmt.Errorf("invalid characters in dbName or userName")
	}

	query := fmt.Sprintf(`
	USE [%s];
	DROP USER [%s];
	`, dbName, userName)

	_, err := c.db.ExecContext(ctx, query)
	if err != nil {
		return err
	}
	return nil
}

// UserPermissionDetails contains detailed information about a user's permissions
type UserPermissionDetails struct {
	PrincipalID         string
	PrincipalName       string
	ServerPermissions   []string
	ServerRoles         []string
	DatabasePermissions map[string][]string // database name -> permissions
	DatabaseRoles       map[string][]string // database name -> roles
}

// GetUserPermissionDetails returns detailed information about what permissions a user has
func (c *Client) GetUserPermissionDetails(ctx context.Context, principalID string) (*UserPermissionDetails, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting detailed permission information", zap.String("principal_id", principalID))

	// Get user info
	user, err := c.GetUserPrincipal(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	details := &UserPermissionDetails{
		PrincipalID:         principalID,
		PrincipalName:       user.Name,
		ServerPermissions:   []string{},
		ServerRoles:         []string{},
		DatabasePermissions: make(map[string][]string),
		DatabaseRoles:       make(map[string][]string),
	}

	// Get server-level permissions (excluding ignored permissions)
	query := `
	SELECT perms.type, perms.state
	FROM sys.server_permissions perms
	WHERE perms.grantee_principal_id = @p1 
	AND (perms.state = 'G' OR perms.state = 'W')
	` + BuildIgnoredPermissionsClause(IgnoredPermissionsForDeletion.Server)
	rows, err := c.db.QueryxContext(ctx, query, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to query server permissions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var permType, state string
		if err := rows.Scan(&permType, &state); err != nil {
			continue
		}
		permStr := permType
		if state == "W" {
			permStr += " (WITH GRANT)"
		}
		details.ServerPermissions = append(details.ServerPermissions, permStr)
	}

	// Get server role memberships
	query = `
	SELECT r.name
	FROM sys.server_role_members rm
	JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
	WHERE rm.member_principal_id = @p1
	`
	rows, err = c.db.QueryxContext(ctx, query, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to query server roles: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var roleName string
		if err := rows.Scan(&roleName); err != nil {
			continue
		}
		details.ServerRoles = append(details.ServerRoles, roleName)
	}

	// Check database-level permissions and role memberships across all databases
	databases, _, err := c.ListDatabases(ctx, &Pager{Size: 1000})
	if err != nil {
		return nil, fmt.Errorf("failed to list databases: %w", err)
	}

	for _, db := range databases {
		if c.skipUnavailableDatabases && db.StateDesc != "ONLINE" {
			continue
		}

		// Check if user exists in this database
		var dbPrincipalID int64
		query = fmt.Sprintf(`
		SELECT principal_id 
		FROM [%s].sys.database_principals 
		WHERE sid = (SELECT sid FROM sys.server_principals WHERE principal_id = @p1)
		AND type IN ('S', 'U', 'C', 'E', 'K')
		`, db.Name)
		err = c.db.GetContext(ctx, &dbPrincipalID, query, principalID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			l.Warn("error checking database principal", zap.String("database", db.Name), zap.Error(err))
			continue
		}

		// Get database-level permissions (excluding ignored permissions)
		query = fmt.Sprintf(`
		SELECT perms.type, perms.state
		FROM [%s].sys.database_permissions perms
		WHERE perms.grantee_principal_id = @p1 
		AND (perms.state = 'G' OR perms.state = 'W')
		AND perms.class = 0 AND perms.major_id = 0
		%s
		`, db.Name, BuildIgnoredPermissionsClause(IgnoredPermissionsForDeletion.Database))
		rows, err = c.db.QueryxContext(ctx, query, dbPrincipalID)
		if err == nil {
			var dbPerms []string
			for rows.Next() {
				var permType, state string
				if err := rows.Scan(&permType, &state); err != nil {
					continue
				}
				permStr := permType
				if state == "W" {
					permStr += " (WITH GRANT)"
				}
				dbPerms = append(dbPerms, permStr)
			}
			rows.Close()
			if len(dbPerms) > 0 {
				details.DatabasePermissions[db.Name] = dbPerms
			}
		}

		// Get database role memberships
		query = fmt.Sprintf(`
		SELECT r.name
		FROM [%s].sys.database_role_members rm
		JOIN [%s].sys.database_principals r ON rm.role_principal_id = r.principal_id
		WHERE rm.member_principal_id = @p1
		`, db.Name, db.Name)
		rows, err = c.db.QueryxContext(ctx, query, dbPrincipalID)
		if err == nil {
			var dbRoles []string
			for rows.Next() {
				var roleName string
				if err := rows.Scan(&roleName); err != nil {
					continue
				}
				dbRoles = append(dbRoles, roleName)
			}
			rows.Close()
			if len(dbRoles) > 0 {
				details.DatabaseRoles[db.Name] = dbRoles
			}
		}
	}

	return details, nil
}

// LoginType represents the SQL Server login type.
type LoginType string

const (
	// LoginTypeWindows represents Windows authentication.
	LoginTypeWindows LoginType = "WINDOWS"
	// LoginTypeSQL represents SQL Server authentication.
	LoginTypeSQL LoginType = "SQL"
	// LoginTypeAzureAD represents Azure AD authentication.
	LoginTypeAzureAD LoginType = "AZURE_AD"
	// LoginTypeEntraID represents Azure Entra ID authentication.
	LoginTypeEntraID LoginType = "ENTRA_ID"
)

// CreateLogin creates a SQL Server login with the specified authentication type.
// For Windows authentication (loginType=WINDOWS):
//   - If domain is provided, it will create the login in the format [DOMAIN\Username]
//   - otherwise it will use just [Username]
//
// For SQL authentication (loginType=SQL):
//   - It requires a password
//   - Domain is ignored
//
// For Azure AD authentication (loginType=AZURE_AD):
//   - It creates from EXTERNAL PROVIDER
//   - Username should be the full Azure AD username/email
//
// For Entra ID authentication (loginType=ENTRA_ID):
//   - It creates from EXTERNAL PROVIDER
//   - Username should be the full Entra ID username/email
func (c *Client) CreateLogin(ctx context.Context, loginType LoginType, username, password string) error {
	l := ctxzap.Extract(ctx)

	var query string
	switch loginType {
	case LoginTypeWindows:
		loginName := fmt.Sprintf("[%s]", username)
		l.Debug("creating windows login", zap.String("login", loginName))
		query = fmt.Sprintf("CREATE LOGIN %s FROM WINDOWS;", loginName)
	case LoginTypeSQL:
		if password == "" {
			return fmt.Errorf("password is required for SQL Server authentication")
		}
		// For SQL Server authentication, only username and password are used
		loginName := fmt.Sprintf("[%s]", username)
		l.Debug("creating SQL login", zap.String("login", loginName))
		query = fmt.Sprintf("CREATE LOGIN %s WITH PASSWORD = '%s';", loginName, password)
	case LoginTypeAzureAD, LoginTypeEntraID:
		// Azure AD and Entra ID use external provider
		loginName := fmt.Sprintf("[%s]", username)
		l.Debug("creating external provider login", zap.String("login", loginName), zap.String("type", string(loginType)))
		query = fmt.Sprintf("CREATE LOGIN %s FROM EXTERNAL PROVIDER;", loginName)
	default:
		return fmt.Errorf("unsupported login type: %s", loginType)
	}

	l.Debug("SQL QUERY", zap.String("q", query))

	_, err := c.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create login: %w", err)
	}

	return nil
}
