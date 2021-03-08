package app

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/spf13/cobra"

	"github.com/beacon/luna/pkg/dao"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// Entry is a record of all information needed to record a vulnerability at a
// later date.
type Entry struct {
	CommonEntry
	Vuln []*claircore.Vulnerability
}

// CommonEntry is an embedded type that's shared between the "normal" Entry type
// and the on-disk json produced by a Store's Load method.
type CommonEntry struct {
	Updater     string
	Fingerprint driver.Fingerprint
	Date        time.Time
}

// DiskEntry to write to exported files
type DiskEntry struct {
	CommonEntry
	Ref  uuid.UUID
	Vuln *claircore.Vulnerability
}

// NewExportCommand export command
func NewExportCommand() *cobra.Command {
	var dsn string
	var exportFrom string
	var exportFileName string
	exportCmd := &cobra.Command{
		Use:  "export",
		Long: "Export vulnerability update package, so other luna can import this package to skip manual updates",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			var from time.Time
			if exportFrom != "" {
				var err error
				const layout = "2006-01-02"
				from, err = time.Parse(layout, exportFrom)
				if err != nil {
					return fmt.Errorf("invalid --from flag, valid values like %s", layout)
				}
			}
			if exportFileName == "" {
				return errors.New("-o is required")
			}
			if err := Export(ctx, dsn, from, exportFileName); err != nil {
				return err
			}
			return nil
		},
	}

	exportCmd.PersistentFlags().StringVarP(&dsn, "dsn", "", "", "DSN to connect to postgres")
	exportCmd.PersistentFlags().StringVarP(&exportFrom, "from", "", "", "Export since time, leaving empty will export everything. Example: 2021-01-12")
	exportCmd.PersistentFlags().StringVarP(&exportFileName, "out", "o", "", "Output filename for the export, better end with .gz")
	return exportCmd
}

// Export vulnerability updates
func Export(ctx context.Context, dsn string, from time.Time, fileName string) error {
	start := time.Now()
	db, err := dao.Connect(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	updaterRepo := dao.NewUpdaterRepo(db)

	lastUpdateOp, err := updaterRepo.GetLastUpdateOperation(ctx)
	if err != nil {
		return err
	}
	if lastUpdateOp != nil {
		fmt.Println("Latest update happened at:", lastUpdateOp.Date.String(),
			"FingerPrint:", lastUpdateOp.Fingerprint,
			"Updater:", lastUpdateOp.Updater)
	} else {
		fmt.Println("No updates")
	}
	// FIXME: count of update_operations is actually smaller than uos matched in uo_vuln relation table
	opCount, vulCount, err := updaterRepo.CountVulnerability(ctx, from)
	if err != nil {
		return errors.Wrap(err, "failed to count vulnerability")
	}
	fmt.Println("Since", from.Local().String(), "Update operations=", opCount, "Vulnerabilities=", vulCount)
	if opCount == 0 {
		fmt.Println("Nothing to be exported, exit")
		os.Exit(0)
	}
	ops, err := updaterRepo.ListUpdateOperations(ctx, from)
	if err != nil {
		return errors.Wrap(err, "failed to list update operations")
	}
	outFile, err := os.Create(fileName)
	if err != nil {
		return errors.Wrap(err, "failed to create file")
	}
	defer outFile.Close()
	gz := gzip.NewWriter(outFile)
	defer gz.Close()
	encoder := json.NewEncoder(gz)
	encoder.SetEscapeHTML(false)
	var vulExportCnt int
	for i, op := range ops {
		// TODO: get vulnerabilities with operations
		vulns, err := updaterRepo.ListVulnerabilities(ctx, op.ID)
		if err != nil {
			return errors.Wrap(err, "failed to list vulnerabilities")
		}
		fmt.Println(op.Updater, op.Fingerprint, "Vulnerability count=", len(vulns))
		diskEntry := &DiskEntry{
			CommonEntry: CommonEntry{
				Updater:     op.Updater,
				Fingerprint: op.Fingerprint,
				Date:        op.Date,
			},
			Ref: op.Ref,
		}
		for _, vuln := range vulns {
			diskEntry.Vuln = vuln
			encoder.Encode(diskEntry)
		}

		vulExportCnt += len(vulns)
		updaterPct := float64(i+1) / float64(len(ops)) * 100.0
		vulPct := float64(vulExportCnt) / float64(vulCount) * 100.0
		fmt.Printf("Export progress: Updater:%.02f %%, Vulnerabilities:%.02f%%\n", updaterPct, vulPct)
	}
	taken := time.Now().Sub(start)
	fmt.Println("Export complete, time taken=", taken)
	return nil
}
