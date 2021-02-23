package app

import (
	"context"
	"fmt"
	"os"
	"text/template"

	"github.com/beacon/luna/pkg/infrascanner"
	"github.com/beacon/luna/pkg/infrascanner/dpkg"
	"github.com/pkg/errors"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln"

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
	infrascanner.Register(&dpkg.Scanner{})

	report := &claircore.IndexReport{
		Packages: make(map[string]*claircore.Package),
	}
	for _, scanner := range infrascanner.Registered() {
		packages, err := scanner.Scan(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to scan with scanner "+scanner.Name())
		}
		for _, pkg := range packages {
			report.Packages[pkg.ID] = pkg
		}
	}
	vul, err := libvuln.New(ctx, &libvuln.Opts{
		ConnString: dsn,
		Migrations: true,
	})
	if err != nil {
		return errors.Wrap(err, "failed to setup libvuln")
	}
	vulReport, err := vul.Scan(ctx, report)
	if err != nil {
		return errors.Wrap(err, "failed to scan vulnerabilities")
	}
	fmt.Println(vulReport)
	scanResult := struct {
		Name   string
		Err    error
		Report *claircore.VulnerabilityReport
	}{
		Name:   "local infrastructure",
		Err:    err,
		Report: vulReport,
	}
	tmpl, err := template.New("vulnerability").Parse(tabwriterTmpl)
	if err != nil {
		return errors.Wrap(err, "failed to parse template")
	}

	if err := tmpl.Execute(os.Stdout, &scanResult); err != nil {
		return errors.Wrap(err, "failed to execute template")
	}
	return nil
}
