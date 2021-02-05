package version

import (
	"fmt"
	"runtime"
)

// Common args
var (
	GitVersion   string
	GitCommit    string
	GitTreeState string
	BuildDate    string
	GoVersion    string = runtime.Version()
	Compiler     string = runtime.Compiler
	Platform     string = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

// Print version info on console
func Print() {
	fmt.Println("Git version:", GitVersion)
	fmt.Println("Git commit:", GitCommit)
	fmt.Println("Git tree state:", GitTreeState)
	fmt.Println("Build date:", BuildDate)
	fmt.Println("Go version:", GoVersion)
	fmt.Println("Compiler:", Compiler)
	fmt.Println("Platform:", Platform)
}
