package dao

import (
	"context"

	"github.com/jinzhu/gorm"
	"github.com/quay/claircore"
)

// PackageRepo deal with package
type PackageRepo interface {
	AmendPackageIDs(context.Context, []*claircore.Package) error
}

// NewPackageRepo new package repo
func NewPackageRepo(db *gorm.DB) PackageRepo {
	return &pkgRepo{db}
}

const tablePackage = "package"

type pkgRepo struct {
	db *gorm.DB
}

func (p *pkgRepo) AmendPackageIDs(context.Context, []*claircore.Package) error {
	return nil
}
