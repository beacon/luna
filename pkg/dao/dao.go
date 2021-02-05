package dao

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib" // imported as driver
	"github.com/jinzhu/gorm"
	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"k8s.io/klog"
)

// Connect to a postgres database
func Connect(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.LogMode(true)
	return db, nil
}

// X start transaction
func X(ctx context.Context, db *sqlx.DB, fn func(tx *sqlx.Tx) error, opts ...*sql.TxOptions) error {
	var opt *sql.TxOptions
	if len(opts) != 0 {
		opt = opts[0]
	}
	tx, err := db.BeginTxx(ctx, opt)
	if err != nil {
		klog.Errorln("failed to do transaction:", err)
		return err
	}
	if err := fn(tx); err != nil {
		if err := tx.Rollback(); err != nil {
			klog.Errorln("failed to rollback transaction:", err)
		}
		return err
	}
	err = tx.Commit()
	if err != nil {
		klog.Errorln("failed to commit transaction:", err)
		if err := tx.Rollback(); err != nil {
			klog.Errorln("failed to rollback transaction:", err)
		}
		return err
	}
	return nil
}

// UpdateOperation db dao
type UpdateOperation struct {
	ID int64

	driver.UpdateOperation `gorm:"embedded"`
}

// UpdaterRepo deal with updates
type UpdaterRepo interface {
	GetLastUpdateOperation(ctx context.Context) (*driver.UpdateOperation, error)
	CountVulnerability(ctx context.Context, since time.Time) (updateOpNum int64, vulNum int64, err error)
	ListUpdateOperations(ctx context.Context, since time.Time) ([]*UpdateOperation, error)
	ListVulnerabilities(ctx context.Context, opID int64) ([]*claircore.Vulnerability, error)
}

type updaterRepo struct {
	db *gorm.DB
}

// NewUpdaterRepo updater repo
func NewUpdaterRepo(db *gorm.DB) UpdaterRepo {
	return &updaterRepo{db: db}
}

const (
	tableUpdateOperation = "update_operation"
)

func (u *updaterRepo) GetLastUpdateOperation(ctx context.Context) (*driver.UpdateOperation, error) {
	var result driver.UpdateOperation
	err := u.db.Table(tableUpdateOperation).First(&result).Order("date DESC").Error
	if gorm.IsRecordNotFoundError(err) {
		return nil, nil
	}
	return &result, err
}

func (u *updaterRepo) CountVulnerability(ctx context.Context, since time.Time) (updateOpNum int64, vulNum int64, err error) {
	var count struct {
		OpCount  int64 `gorm:"op_count"`
		VulCount int64 `gorm:"vul_count"`
	}
	u.db.Raw(`SELECT COUNT(distinct uo_vuln.uo) AS op_count,
COUNT(uo_vuln.vuln) AS vul_count 
FROM update_operation, uo_vuln 
WHERE update_operation.date>$1 AND update_operation.id=uo_vuln.uo`, since).Find(&count)
	if err != nil {
		return
	}
	updateOpNum = count.OpCount
	vulNum = count.VulCount
	return
}

func (u *updaterRepo) ListUpdateOperations(ctx context.Context, since time.Time) ([]*UpdateOperation, error) {
	result := make([]*UpdateOperation, 0)
	err := u.db.Table(tableUpdateOperation).Where("date>$1", since).Find(&result).Error
	if gorm.IsRecordNotFoundError(err) {
		return result, nil
	}

	return result, err
}

func (u *updaterRepo) ListVulnerabilities(ctx context.Context, opID int64) ([]*claircore.Vulnerability, error) {
	tmp := make([]*Vulnerability, 0)
	//select vuln.* FROM vuln, uo_vuln where uo_vuln.uo=465 and uo_vuln.vuln=vuln.id
	err := u.db.Raw(`SELECT vuln.* FROM vuln, uo_vuln WHERE uo_vuln.uo=$1 AND uo_vuln.vuln=vuln.id`, opID).Find(&tmp).Error
	if gorm.IsRecordNotFoundError(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]*claircore.Vulnerability, len(tmp))
	for i, v := range tmp {
		result[i] = VulnerabilityToClair(v)
	}
	return result, err
}
