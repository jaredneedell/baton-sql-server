package connector

import (
	"context"

	"github.com/conductorone/baton-sql-server/pkg/mssqldb"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// revokeC1EntitlementIfNoPermissions checks if a user has remaining permissions and revokes
// the C1 app entitlement if they only have connect permissions remaining.
// This replaces the auto-delete functionality.
func revokeC1EntitlementIfNoPermissions(ctx context.Context, c1ApiClient *c1ApiClient, userID, userName string, hasPermissions bool, checkErr error, logFields ...zap.Field) {
	if c1ApiClient == nil {
		// C1 API not configured, skip
		return
	}

	l := ctxzap.Extract(ctx)
	if checkErr != nil {
		l.Warn("failed to check remaining permissions, skipping C1 entitlement revocation", append(logFields, zap.Error(checkErr))...)
		return
	}

	if !hasPermissions {
		// User only has connect permissions remaining (or no permissions at all)
		// Revoke C1 app entitlement
		l.Info("user has no meaningful permissions remaining, revoking C1 app entitlement", logFields...)
		if err := c1ApiClient.revokeEntitlementForUser(ctx, userName); err != nil {
			l.Warn("failed to revoke C1 app entitlement",
				append(logFields, zap.String("user_id", userID), zap.Error(err))...)
			// Don't fail the revoke operation if entitlement revocation fails
		}
	} else {
		l.Debug("user still has meaningful permissions, not revoking C1 entitlement", logFields...)
	}
}

// checkAndRevokeC1EntitlementForServer checks if a user has any remaining server-level permissions
// (excluding connect permissions). If the user only has connect permissions remaining, it revokes
// the C1 app entitlement via API call.
func checkAndRevokeC1EntitlementForServer(ctx context.Context, client *mssqldb.Client, userID, userName string, c1ApiClient *c1ApiClient) {
	hasPermissions, err := client.UserHasRemainingServerPermissions(ctx, userID)
	revokeC1EntitlementIfNoPermissions(ctx, c1ApiClient, userID, userName, hasPermissions, err,
		zap.String("user", userName))
}

// checkAndRevokeC1EntitlementForDatabase checks if a user has any remaining permissions in a specific database
// (excluding connect permissions). If the user only has connect permissions remaining in that database,
// it also checks server-level permissions. If the user has no meaningful permissions anywhere,
// it revokes the C1 app entitlement via API call.
func checkAndRevokeC1EntitlementForDatabase(ctx context.Context, client *mssqldb.Client, userID, userName, dbName string, c1ApiClient *c1ApiClient) {
	l := ctxzap.Extract(ctx)

	// Check if user has remaining permissions in this database (excluding connect)
	hasDbPermissions, err := client.UserHasRemainingDatabasePermissions(ctx, userID, dbName)
	if err != nil {
		l.Warn("failed to check remaining database permissions, skipping C1 entitlement revocation",
			zap.String("database", dbName), zap.Error(err))
		return
	}

	if !hasDbPermissions {
		// User has no meaningful permissions in this database
		// Check if they have any server-level permissions
		hasServerPermissions, err := client.UserHasRemainingServerPermissions(ctx, userID)
		if err != nil {
			l.Warn("failed to check remaining server permissions, skipping C1 entitlement revocation", zap.Error(err))
			return
		}

		// Revoke if no server permissions either
		revokeC1EntitlementIfNoPermissions(ctx, c1ApiClient, userID, userName, hasServerPermissions, nil,
			zap.String("user", userName),
			zap.String("database", dbName))
	} else {
		l.Debug("user still has meaningful database permissions, not revoking C1 entitlement",
			zap.String("user", userName),
			zap.String("database", dbName))
	}
}
