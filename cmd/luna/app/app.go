package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/beacon/luna/pkg/version"
)

// NewLunaCommand create command for luna controller
// klog provided hidden flags and must use flag.Parse() before using klog
func NewLunaCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "luna",
		Long: `The luna provides protected API wrapper for vulnerability datastore and live updates, 
imports/exports of vulnerability store, management of scanning tasks, etc.
`,
		SilenceUsage: true,
	}
	versionCmd := &cobra.Command{
		Use: "version",
		Run: func(cmd *cobra.Command, args []string) {
			version.Print()
			os.Exit(0)
		},
	}
	cmd.AddCommand(versionCmd)
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

	exportCmd.PersistentFlags().StringVarP(&dsn, "dsn", "", "", "DNS to connect to postgres")
	exportCmd.PersistentFlags().StringVarP(&exportFrom, "from", "", "", "Export since time, leaving empty will export everything. Example: 2021-01-12")
	exportCmd.PersistentFlags().StringVarP(&exportFileName, "out", "o", "", "Output filename for the export, better end with .gz")
	cmd.AddCommand(exportCmd)

	return cmd
}
