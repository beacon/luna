package main

import (
	"os"

	"k8s.io/klog"

	"github.com/beacon/luna/cmd/luna/app"
)

func main() {
	defer klog.Flush()
	command := app.NewLunaCommand()
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
