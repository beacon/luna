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

	exportCmd.PersistentFlags().StringVarP(&dsn, "dsn", "", "", "DSN to connect to postgres")
	exportCmd.PersistentFlags().StringVarP(&exportFrom, "from", "", "", "Export since time, leaving empty will export everything. Example: 2021-01-12")
	exportCmd.PersistentFlags().StringVarP(&exportFileName, "out", "o", "", "Output filename for the export, better end with .gz")
	cmd.AddCommand(exportCmd)

	var importFileName string
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
	cmd.AddCommand(importCmd)

	inspectCmd := &cobra.Command{
		Use:  "inspect",
		Long: "Inspect image",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Args:", args)
			m, err := Inspect(context.Background(), args[0])
			if err != nil {
				return err
			}
			raw, _ := json.MarshalIndent(m, "", "  ")
			fmt.Println(string(raw))
			return nil
		},
	}
	cmd.AddCommand(inspectCmd)

	scanCmd := &cobra.Command{
		Use:  "scan",
		Long: "Scan image",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				return errors.New("missing dsn argument")
			}
			err := ScanLocal(context.Background(), args[0], dsn)
			return err
		},
	}
	scanCmd.PersistentFlags().StringVarP(&dsn, "dsn", "", "", "DSN for the database to be migrated")
	cmd.AddCommand(scanCmd)

	cmd.AddCommand(NewUpdateCommand())
	cmd.AddCommand(NewInfraScanCommand())

	return cmd
}
