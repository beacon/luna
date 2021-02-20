package app

import (
	"context"

	"github.com/pkg/errors"
	"github.com/quay/claircore/libvuln"
	_ "github.com/quay/claircore/updater/defaults" // register updaters. Only available >= v0.3.1
	"github.com/spf13/cobra"
)

// NewUpdateCommand new command
func NewUpdateCommand() *cobra.Command {
	var dsn string
	cmd := &cobra.Command{
		Use:  "update",
		Long: "Update vulnerability database",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				return errors.New("missing dsn argument")
			}
			err := Update(context.Background(), dsn)
			return err
		},
	}
	cmd.PersistentFlags().StringVarP(&dsn, "dsn", "", "", "DSN for the database to be migrated")
	return cmd
}

// Update do an update online
func Update(ctx context.Context, dsn string) error {
	opts := &libvuln.Opts{
		ConnString:  dsn,
		Migrations:  true,
		MaxConnPool: 32,
	}

	// do this simply to initialize tables if not exists
	vuln, err := libvuln.New(ctx, opts)
	if err != nil {
		return errors.Wrap(err, "failed to setup index")
	}
	err = vuln.FetchUpdates(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to create new updater")
	}

	return nil
}
