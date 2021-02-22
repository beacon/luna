/*
Package infrascanner provide package list from non-image environment, instead of image layer
*/
package infrascanner

import (
	"context"

	"github.com/quay/claircore"
)

// Scanner interface
type Scanner interface {
	Name() string
	Kind() string
	Version() string
	Scan(context.Context) ([]*claircore.Package, error)
}
