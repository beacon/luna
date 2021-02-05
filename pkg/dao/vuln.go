package dao

import (
	"encoding/json"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

// Vulnerability is the gorm dao for claircore@v1.0.5
// All fields should be modified to corresponding claircore package
// Should not be changed at will
type Vulnerability struct {
	// unique ID of this vulnerability. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string
	// the updater that discovered this vulnerability
	Updater string
	// the name of the vulnerability. for example if the vulnerability exists in a CVE database this
	// would the unique CVE name such as CVE-2017-11722
	Name string
	// the description of the vulnerability
	Description string
	// the timestamp when vulnerability was issued
	Issued time.Time
	// any links to more details about the vulnerability
	Links string
	// the severity string retrieved from the security database
	Severity string
	// a normalized Severity type providing client guaranteed severity information
	NormalizedSeverity claircore.Severity

	// the package information associated with the vulnerability. ideally these fields can be matched
	// to packages discovered by libindex PackageScanner structs.
	Package *VulPackage `gorm:"EMBEDDED;EMBEDDED_PREFIX:package_"`
	// the distribution information associated with the vulnerability.
	Dist *VulDist `gorm:"EMBEDDED;EMBEDDED_PREFIX:dist_"`
	// the repository information associated with the vulnerability
	Repo *VulRepository `gorm:"EMBEDDED;EMBEDDED_PREFIX:repo_"`
	// a string specifying the package version the fix was released in
	FixedInVersion string `gorm:"fixed_in_version"`
	// Range describes the range of versions that are vulnerable.
	RawRange []byte          `gorm:"range"`
	Range    claircore.Range `json:"-"`
}

// AfterFind marshal range
func (v *Vulnerability) AfterFind(scope *gorm.Scope) (err error) {
	if len(v.RawRange) == 0 {
		return
	}
	err = json.Unmarshal(v.RawRange, &v.Range)
	if err != nil {
		return errors.Wrap(err, "json unmarshal failed")
	}
	return
}

// VulnerabilityToClair vulnerabity db record to clair form
func VulnerabilityToClair(v *Vulnerability) *claircore.Vulnerability {

	cv := &claircore.Vulnerability{
		ID:                 v.ID,
		Updater:            v.Updater,
		Name:               v.Name,
		Description:        v.Description,
		Issued:             v.Issued,
		Links:              v.Links,
		Severity:           v.Severity,
		NormalizedSeverity: v.NormalizedSeverity,
		Package: &claircore.Package{
			Name:    v.Package.Name,
			Version: v.Package.Version,
			Kind:    v.Package.Kind,
			Module:  v.Package.Module,
			Arch:    v.Package.Arch,
		},
		Dist: &claircore.Distribution{
			ID:              v.Dist.ID,
			Name:            v.Dist.Name,
			Version:         v.Dist.Version,
			VersionID:       v.Dist.VersionID,
			VersionCodeName: v.Dist.VersionCodeName,
			Arch:            v.Dist.Arch,
			CPE:             v.Dist.CPE,
			PrettyName:      v.Dist.PrettyName,
		},
		Repo: &claircore.Repository{
			Name: v.Repo.Name,
			Key:  v.Repo.Key,
			URI:  v.Repo.URI,
		},
		FixedInVersion: v.FixedInVersion,
		Range:          &v.Range,
	}
	return cv
}

// !IMPORTANT: Below embedded fields in table should remove members that non-exists in vuln table, to avoid misuse.

// VulPackage represent related package_* fields in table vuln
type VulPackage struct {
	// the name of the package
	Name string `gorm:"name"`
	// the version of the package
	Version string
	// type of package. currently expectations are binary or source
	Kind string
	// Module and stream which this package is part of
	Module string
	// Package architecture
	Arch string
}

// VulDist dist_* fields in table vuln
type VulDist struct {
	// unique ID of this distribution. this will be created as discovered by the library
	// and used for persistence and hash map indexes.
	ID string
	// A string identifying the operating system.
	// example: "Ubuntu"
	Name string
	// A string identifying the operating system version, excluding any OS name information,
	// possibly including a release code name, and suitable for presentation to the user.
	// example: "16.04.6 LTS (Xenial Xerus)"
	Version string

	// A lower-case string (mostly numeric, no spaces or other characters outside of 0–9, a–z, ".", "_" and "-")
	// identifying the operating system version, excluding any OS name information or release code name,
	// example: "16.04"
	VersionID string
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system release code name,
	// excluding any OS name information or release version, and suitable for processing by scripts or usage in generated filenames
	// example: "xenial"
	VersionCodeName string

	// A string identifying the OS architecture
	// example: "x86_64"
	Arch string
	// Optional common platform enumeration identifier
	CPE cpe.WFN
	// A pretty operating system name in a format suitable for presentation to the user.
	// May or may not contain a release code name or OS version of some kind, as suitable. If not set, defaults to "PRETTY_NAME="Linux"".
	// example: "PRETTY_NAME="Fedora 17 (Beefy Miracle)"".
	PrettyName string
}

// VulRepository is a package repository
type VulRepository struct {
	Name string
	Key  string
	URI  string
}
