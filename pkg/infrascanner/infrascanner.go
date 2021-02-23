/*
Package infrascanner provide package list from non-image environment, instead of image layer
*/
package infrascanner

import (
	"context"

	"github.com/quay/claircore"
)

var scanners []Scanner

// Scanner interface
type Scanner interface {
	Name() string
	Kind() string
	Version() string
	Scan(context.Context) ([]*claircore.Package, error)
}

// Register add one more scanner
func Register(s Scanner) {
	scanners = append(scanners, s)
}

// Registered return registered scanners
func Registered() []Scanner {
	return scanners
}
