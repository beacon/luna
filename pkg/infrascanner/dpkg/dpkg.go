/*
Package dpkg provide local scanner for systems using dpkg: ubuntu, debian, etc
*/
package dpkg

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/pkg/errors"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
	"github.com/tadasv/go-dpkg"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
)

const (
	name    = "dpkg"
	kind    = "package"
	version = "v0.0.1"
)

type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (ps *Scanner) Name() string { return name }

// Version implements scanner.VersionedScanner.
func (ps *Scanner) Version() string { return version }

// Kind implements scanner.VersionedScanner.
func (ps *Scanner) Kind() string { return kind }

// Scan attempts to find a dpkg database within the layer and read all of the
// installed packages it can find in the "status" file.
//
// It's expected to return (nil, nil) if there's no dpkg database in the layer.
//
// It does not respect any dpkg configuration files.
func (ps *Scanner) Scan(ctx context.Context) ([]*claircore.Package, error) {
	// Preamble
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	loc := map[string]int{
		"/var/lib/dpkg": 2,
	}

	// If we didn't find anything, this loop is completely skipped.
	var pkgs []*claircore.Package
	for p, x := range loc {
		if x != 2 { // If we didn't find both files, skip this directory.
			continue
		}
		ctx = baggage.ContextWithValues(ctx, label.String("database", p))
		zlog.Debug(ctx).Msg("examining package database")

		// We want the "status" file, so search the archive for it.
		statusFile := filepath.Join(p, "status")
		rawContent, err := ioutil.ReadFile(statusFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open file:"+p)
		}
		// Take all the packages found in the database and attach to the slice
		// defined outside the loop.
		found := make(map[string]*claircore.Package)
		dbPkgs := dpkg.NewParser(bytes.NewReader(rawContent)).Parse()
		zlog.Debug(ctx).Int("package num", len(pkgs)).Msg("package num")
		for _, pkg := range dbPkgs {
			p := &claircore.Package{
				Name:      pkg.Package,
				Version:   pkg.Version,
				Kind:      claircore.BINARY,
				Arch:      pkg.Architecture,
				PackageDB: statusFile,
			}
			if pkg.Source != "" {
				p.Source = &claircore.Package{
					Name: pkg.Source,
					Kind: claircore.SOURCE,
					// Right now, this is an assumption that discovered source
					// packages relate to their binary versions. We see this in
					// Debian.
					Version:   pkg.Version,
					PackageDB: statusFile,
				}
			}

			found[p.Name] = p
			zlog.Debug(ctx).Str("package", pkg.Package).Msg("added package")
			pkgs = append(pkgs, p)
		}

		infoDir := filepath.Join(p, "info")
		const suffix = ".md5sums"
		infos, err := ioutil.ReadDir(infoDir)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read dir:"+infoDir)
		}
		for _, info := range infos {
			if !strings.HasSuffix(info.Name(), suffix) {
				continue
			}
			n := filepath.Base(info.Name())
			n = strings.TrimSuffix(n, suffix)
			if i := strings.IndexRune(n, ':'); i != -1 {
				n = n[:i]
			}
			p, ok := found[n]
			if !ok {
				zlog.Debug(ctx).
					Str("package", n).
					Msg("extra metadata found, ignoring")
				continue
			}
			sumFileName := path.Join(infoDir, info.Name())
			sumFile, err := os.Open(sumFileName)
			if err != nil {
				return nil, errors.Wrap(err, "failed to open sum file:"+sumFileName)
			}
			hash := md5.New()
			if _, err := io.Copy(hash, sumFile); err != nil {
				zlog.Warn(ctx).
					Err(err).
					Str("package", n).
					Msg("unable to read package metadata")
				continue
			}
			sumFile.Close()
			p.RepositoryHint = hex.EncodeToString(hash.Sum(nil))
		}
		zlog.Debug(ctx).
			Int("count", len(found)).
			Msg("found packages")
	}

	return pkgs, nil
}
