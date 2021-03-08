package app

import (
	"context"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewImportCommand() *cobra.Command {
	// TODO: move it into a single package
	var importFileName string
	var dsn string
	importCmd := &cobra.Command{
		Use:  "import",
		Long: "Import offline update package from a file, and load it into new database. Migrations will be done automatically",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if importFileName == "" {
				return errors.New("-i is required")
			}
			if dsn == "" {
				return errors.New("--dsn is required")
			}
			return Import(ctx, importFileName, dsn)
		},
	}
	importCmd.PersistentFlags().StringVarP(&dsn, "dsn", "", "", "DSN for the database to be migrated")
	importCmd.PersistentFlags().StringVarP(&importFileName, "in", "i", "", "Input update package")
	return importCmd
}

// Import import an update package and load it into specified database
func Import(ctx context.Context, srcFile string, dsn string) error {
	opts := &libvuln.Opts{
		ConnString: dsn,
		Migrations: true,
	}

	l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: true}).
		Level(zerolog.DebugLevel).With().
		Timestamp().Caller().Logger()
	zlog.Set(&l)
	ctx = l.WithContext(ctx)

	_, err := libvuln.New(ctx, opts)
	if err != nil {
		return errors.Wrap(err, "failed to setup index")
	}

	f, err := os.Open(srcFile)
	if err != nil {
		return errors.Wrap(err, "failed to open update package")
	}
	defer f.Close()
	pool, err := pgxpool.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := libvuln.OfflineImport(ctx, pool, f); err != nil {
		return err
	}
	return nil
}
