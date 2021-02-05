package app

import (
	"context"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"
)

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
