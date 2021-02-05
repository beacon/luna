package app

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

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
		entry := &Entry{
			CommonEntry: CommonEntry{
				Updater:     op.Updater,
				Fingerprint: op.Fingerprint,
				Date:        op.Date,
			},
			Vuln: vulns,
		}
		encoder.Encode(entry)
		vulExportCnt += len(vulns)
		updaterPct := float64(i+1) / float64(len(ops)) * 100.0
		vulPct := float64(vulExportCnt) / float64(vulCount) * 100.0
		fmt.Printf("Export progress: Updater:%.02f %%, Vulnerabilities:%.02f%%\n", updaterPct, vulPct)
	}
	taken := time.Now().Sub(start)
	fmt.Println("Export complete, time taken=", taken)
	return nil
}
