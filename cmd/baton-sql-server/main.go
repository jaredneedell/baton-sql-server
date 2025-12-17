package main

import (
	"context"
	"fmt"
	"os"

	"path/filepath"

	config "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/conductorone/baton-sql-server/pkg/connector"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var version = "dev"

func getConfigDir(name string) string {
	return filepath.Join(os.Getenv("PROGRAMDATA"), "ConductorOne", name)
}

func main() {
	ctx := context.Background()

	connectorName := "baton-sql-server"
	configPath := os.Getenv("BATON_CONFIG_PATH")
	if configPath == "" && os.Getenv("PROGRAMDATA") != "" {
		// Set BATON_CONFIG_PATH so that if we're running as a windows service, we use the correct config file
		err := os.Setenv("BATON_CONFIG_PATH", filepath.Join(getConfigDir(connectorName), "config.yaml"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	_, cmd, err := config.DefineConfiguration(ctx, connectorName, getConnector, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	// Build DSN from either provided DSN string or db-host/db-port with integrated auth
	dsnValue := v.GetString(dsn.FieldName)
	if dsnValue == "" {
		// Use db-host and db-port for Windows integrated authentication
		dbHostValue := v.GetString(dbHost.FieldName)
		dbPortValue := v.GetString(dbPort.FieldName)

		if dbHostValue == "" {
			return nil, fmt.Errorf("either dsn or db-host must be provided")
		}

		// Default port to 1433 if not provided
		if dbPortValue == "" {
			dbPortValue = "1433"
		}

		// Build DSN with Windows integrated authentication
		dsnValue = fmt.Sprintf("server=%s;port=%s;Integrated Security=true;Trusted_Connection=true", dbHostValue, dbPortValue)
		l.Info("using Windows integrated authentication", zap.String("host", dbHostValue), zap.String("port", dbPortValue))
	}

	cb, err := connector.New(ctx, dsnValue, v.GetBool(skipUnavailableDatabases.FieldName), v.GetString(appName.FieldName), v.GetBool(autoDeleteOrphanedLogins.FieldName), v.GetString(windowsLoginEmailDomain.FieldName), v.GetString(c1ApiClientId.FieldName), v.GetString(c1ApiClientSecret.FieldName), v.GetString(c1AppId.FieldName), v.GetString(c1EntitlementId.FieldName))
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	c, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		return nil, err
	}

	return c, nil
}
