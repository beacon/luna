package app

import (
	"context"

	"github.com/pkg/errors"

	"github.com/spf13/cobra"
)

// NewInfraScanCommand scans infrastruture
func NewInfraScanCommand() *cobra.Command {
	var dsn string
	cmd := &cobra.Command{
		Use:  "infra",
		Long: "Scan local infrastructure",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				return errors.New("missing dsn argument")
			}
			err := ScanInfra(context.Background(), dsn)
			return err
		},
	}
	cmd.PersistentFlags().StringVarP(&dsn, "dsn", "", "", "DSN for the database to be migrated")

	return cmd
}

// ScanInfra scan infra
func ScanInfra(ctx context.Context, dsn string) error {
	// TODO: implement this
	return nil
}
