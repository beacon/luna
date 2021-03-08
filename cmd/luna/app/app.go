package app

import (
	"os"

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
	cmd.AddCommand(NewExportCommand())
	cmd.AddCommand(NewImportCommand())
	cmd.AddCommand(NewInspectCommand())
	cmd.AddCommand(NewScanCommand())
	cmd.AddCommand(NewUpdateCommand())
	cmd.AddCommand(NewInfraScanCommand())

	return cmd
}
