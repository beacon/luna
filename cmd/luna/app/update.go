package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/updater"
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
	pool, err := pgxpool.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	// do this simply to initialize tables if not exists
	if _, err := libvuln.New(ctx, &libvuln.Opts{
		ConnString: dsn,
		Migrations: true,
	}); err != nil {
		return errors.Wrap(err, "failed to setup index")
	}
	u, err := libvuln.NewUpdater(pool, http.DefaultClient, nil, 4, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create new updater")
	}

	d := updater.Registered()
	ufs := make([]driver.UpdaterSetFactory, 0, len(d))
	for _, f := range d {
		ufs = append(ufs, f)
	}
	fmt.Println("DBG - updater num=", len(ufs))
	if err := u.RunUpdaters(ctx, ufs...); err != nil {
		return errors.Wrap(err, "failed to run updaters")
	}
	return nil
}
