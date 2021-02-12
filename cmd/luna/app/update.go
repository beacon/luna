package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
	"github.com/quay/claircore/updater"
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
	if err := registerUpdaters(ctx); err != nil {
		return errors.Wrap(err, "failed to register updaters")
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

// It's kind of weird that package defaults is not present in claircore package
// Interesting to find out more details
func registerUpdaters(ctx context.Context) error {
	rf, err := rhel.NewFactory(ctx, rhel.DefaultManifest)
	if err != nil {
		return err
	}
	updater.Register("rhel", rf)

	updater.Register("ubuntu", &ubuntu.Factory{Releases: ubuntu.Releases})
	updater.Register("alpine", driver.UpdaterSetFactoryFunc(alpine.UpdaterSet))
	updater.Register("aws", driver.UpdaterSetFactoryFunc(aws.UpdaterSet))
	updater.Register("debian", driver.UpdaterSetFactoryFunc(debian.UpdaterSet))
	updater.Register("oracle", driver.UpdaterSetFactoryFunc(oracle.UpdaterSet))
	updater.Register("photon", driver.UpdaterSetFactoryFunc(photon.UpdaterSet))

	// Strange...
	// updater.Register("pyupio", driver.UpdaterSetFactoryFunc(pyupio.UpdaterSet))
	updater.Register("suse", driver.UpdaterSetFactoryFunc(suse.UpdaterSet))
	return nil
}
