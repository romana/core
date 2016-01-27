package common

import (
	"github.com/jinzhu/gorm"
	"log"
	"errors"
	_ "github.com/go-sql-driver/mysql"
)

type GormStore struct {
	connStr string
	db      *gorm.DB
}
