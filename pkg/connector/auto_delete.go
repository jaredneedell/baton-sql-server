package connector

import (
	"context"

	"github.com/conductorone/baton-sql-server/pkg/mssqldb"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// checkAndDeleteOrphanedDatabaseUser checks if a user has remaining permissions in a specific database
// and deletes the user from that database if auto-delete is enabled and the user has no meaningful permissions remaining.
// This is called after revoking a database role.
func checkAndDeleteOrphanedDatabaseUser(ctx context.Context, client *mssqldb.Client, autoDeleteEnabled bool, userID, userName, dbName string) {
	if !autoDeleteEnabled {
		return
	}

	l := ctxzap.Extract(ctx)
	hasPermissions, err := client.UserHasRemainingDatabasePermissions(ctx, userID, dbName)
	if err != nil {
		l.Warn("failed to check remaining database permissions, skipping auto-delete", zap.String("database", dbName), zap.Error(err))
		return
	}

	if !hasPermissions {
		l.Info("user has no remaining permissions in database, deleting user from database", zap.String("user", userName), zap.String("database", dbName))
		err = client.DeleteUserFromDatabase(ctx, dbName, userName)
		if err != nil {
			l.Warn("failed to delete orphaned database user", zap.String("user", userName), zap.String("database", dbName), zap.Error(err))
			// Don't fail the revoke operation if delete fails
			return
		}

	} else {
		l.Debug("user still has permissions in database, not deleting", zap.String("user", userName), zap.String("database", dbName))
	}
}

// checkAndDeleteOrphanedServerLogin checks if a user has remaining server-level permissions
// and deletes the server login if auto-delete is enabled and the user has no meaningful permissions remaining.
// This is called after revoking a server role.
func checkAndDeleteOrphanedServerLogin(ctx context.Context, client *mssqldb.Client, autoDeleteEnabled bool, userID, userName string) {
	if !autoDeleteEnabled {
		return
	}

	l := ctxzap.Extract(ctx)
	hasPermissions, err := client.UserHasRemainingServerPermissions(ctx, userID)
	if err != nil {
		l.Warn("failed to check remaining server permissions, skipping auto-delete", zap.Error(err))
		return
	}

	if !hasPermissions {
		l.Info("user has no remaining server permissions, deleting login", zap.String("user", userName))
		err = client.DeleteUserFromServer(ctx, userName)
		if err != nil {
			l.Warn("failed to delete orphaned login", zap.String("user", userName), zap.Error(err))
			// Don't fail the revoke operation if delete fails
			return
		}

	} else {
		// User still has server permissions - log details for debugging
		details, err := client.GetUserPermissionDetails(ctx, userID)
		if err != nil {
			l.Warn("failed to get permission details for debugging", zap.Error(err))
		} else {
			l.Info("user still has server permissions, not deleting",
				zap.String("user", userName),
				zap.Strings("server_permissions", details.ServerPermissions),
				zap.Strings("server_roles", details.ServerRoles),
			)
		}
	}
}

