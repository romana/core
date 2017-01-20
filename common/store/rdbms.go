// Copyright (c) 2016-2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package store provides
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/romana/core/common"
	log "github.com/romana/rlog"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// createSchema is a type for functions that create database schemas.
// By defining a type we can more easily store references to functions of
// the specified signature.
type createSchema func(dbStore *DbStore, force bool) error

// DbStore is a to-be-deprecated structure storing information specific to RDBMS-based
// implementation of Store.
type DbStore struct {
	common.ServiceStore
	Config            *common.StoreConfig
	Db                *gorm.DB
	createSchemaFuncs map[string]createSchema
}

// Find generically implements Find() of Store interface
// for DbStore
func (dbStore *DbStore) Find(query url.Values, entities interface{}, flag common.FindFlag) (interface{}, error) {
	queryStringFieldToDbField := make(map[string]string)
	// Since entities array exists for reflection purposes
	// we need to create a new array to put found data into.
	// Otherwise we'd be reusing the same object and race conditions
	// will result.
	ptrToArrayType := reflect.TypeOf(entities)
	arrayType := ptrToArrayType.Elem()
	newEntities := reflect.New(arrayType).Interface()
	t := reflect.TypeOf(newEntities).Elem().Elem()
	for i := 0; i < t.NumField(); i++ {
		structField := t.Field(i)
		fieldTag := structField.Tag
		fieldName := structField.Name

		queryStringField := strings.ToLower(fieldName)
		dbField := strings.ToLower(fieldName)
		if fieldTag == "" {
			// If there is no tag, then query variable is just the same as
			// the fieldName...
			log.Infof("No tag for %s", fieldName)
		} else {
			jTag := fieldTag.Get("json")
			if jTag == "" {
				log.Infof("No JSON tag for %s", fieldName)
			} else {
				jTagElts := strings.Split(jTag, ",")
				// This takes care of ",omitempty"
				if len(jTagElts) > 1 {
					queryStringField = jTagElts[0]
				} else {
					queryStringField = jTag
				}
			}
			gormTag := fieldTag.Get("gorm")
			//			log.Infof("Gorm tag for %s: %s (%v)", fieldName, gormTag, fieldTag)
			if gormTag != "" {
				// See model_struct.go:parseTagSetting
				gormVals := strings.Split(gormTag, ";")
				for _, gormVal := range gormVals {
					elts := strings.Split(gormVal, ":")
					if len(elts) == 0 {
						continue
					}
					k := strings.TrimSpace(strings.ToUpper(elts[0]))
					if k == "COLUMN" {
						if len(elts) != 2 {
							return nil, common.NewError400(fmt.Sprintf("Expected 2 elements in %s (in %s)", gormVal, gormTag))
						}
						dbField = elts[1]
						break
					}

				}
			}
		}
		//		log.Infof("For %s, query string field %s, struct field %s, DB field %s", t, queryStringField, fieldName, dbField)
		queryStringFieldToDbField[queryStringField] = dbField
	}
	whereMap := make(map[string]interface{})

	for k, v := range query {
		k = strings.ToLower(k)
		dbFieldName := queryStringFieldToDbField[k]
		if dbFieldName == "" {
			return nil, common.NewError400(fmt.Sprintf("Unknown field %s in %v", k, t))
		}
		if len(v) > 1 {
			return nil, common.NewError400("Did not expect multiple values in " + k)
		}
		whereMap[dbFieldName] = v[0]
	}

	//	log.Infof("Store: Querying with %+v - %T", whereMap, newEntities)

	var db *gorm.DB

	if flag == common.FindFirst || flag == common.FindLast {
		var count int
		entityPtrVal := reflect.New(reflect.TypeOf(newEntities).Elem().Elem())
		entityPtr := entityPtrVal.Interface()
		if flag == common.FindFirst {
			db = dbStore.Db.Where(whereMap).First(entityPtr).Count(&count)
		} else {
			db = dbStore.Db.Where(whereMap).Last(entityPtr).Count(&count)
		}
		err := common.GetDbErrors(db)
		if err != nil {
			return nil, err
		}
		if count == 0 {
			return nil, common.NewError404(t.String(), fmt.Sprintf("%+v", whereMap))
		}
		return entityPtr, nil
	}

	db = dbStore.Db.Where(whereMap).Find(newEntities)
	err := common.GetDbErrors(db)
	if err != nil {
		return nil, err
	}
	rowCount := reflect.ValueOf(newEntities).Elem().Len()

	if rowCount == 0 {
		return nil, common.NewError404(t.String(), fmt.Sprintf("%+v", whereMap))
	}

	if flag == common.FindExactlyOne {
		if rowCount == 1 {
			return reflect.ValueOf(newEntities).Elem().Index(0).Interface(), nil
		} else {
			return nil, common.NewError500(fmt.Sprintf("Multiple results found for %+v: %+v", query, reflect.ValueOf(newEntities).Elem().Interface()))
		}
	}

	return newEntities, nil
}

// SetConfig sets the config object from a map.
func (dbStore *DbStore) SetConfig(config common.StoreConfig) error {
	dbStore.Config = &config
	dbStore.createSchemaFuncs = make(map[string]createSchema)
	dbStore.createSchemaFuncs["mysql"] = createSchemaMysql
	dbStore.createSchemaFuncs["sqlite3"] = createSchemaSqlite3
	return nil
}

// GetPasswordFunction returns appropriate function to hash
// password depending on the underlying DB (note that in sqlite
// it is plain text).
func (dbStore *DbStore) GetPasswordFunction() (string, error) {
	switch dbStore.Config.Type {
	case "mysql":
		return "MD5(?)", nil
	case "sqlite3":
		return "?", nil
	}
	return "", errors.New(fmt.Sprintf("Unknown database: %s", dbStore.Config.Type))
}

func (dbStore *DbStore) DbStore() DbStore {
	return *dbStore
}

// connectDB gets multiple connection strings and
// tries to connect to them till it is successful.
func (dbStore *DbStore) connectDB() error {
	var errs []error
	if dbStore.Config == nil {
		return errors.New("No configuration specified.")
	}
	connStrs := dbStore.getConnStrings()
	for _, str := range connStrs {
		fmt.Println("dbStore.Config.Type: ", dbStore.Config.Type)
		fmt.Println("str: ", str)
		db, err := gorm.Open(dbStore.Config.Type, str)
		if err == nil {
			if dbStore.Config.Type == "sqlite3" {
				db.DB().SetMaxOpenConns(1)
			}
			dbStore.Db = db
			return nil
		}
		errs = append(errs, err)
	}

	var errsStr string
	for i, e := range errs {
		if i == 0 {
			errsStr = fmt.Sprintf("%s", e)
		} else {
			errsStr = fmt.Sprintf("%s\n%s", errsStr, e)
		}
	}
	return fmt.Errorf(errsStr)
}

// getConnStrings returns the appropriate GORM connection string for
// the given DB.
func (dbStore *DbStore) getConnStrings() []string {
	var connStr []string
	info := dbStore.Config
	switch info.Type {
	case "sqlite3":
		connStr = append(connStr, info.Database)
		log.Infof("DB: Connection string: %s", info.Database)
	default:
		portStr := fmt.Sprintf(":%d", info.Port)
		if info.Port == 0 {
			portStr = ":3306"
		}
		connStr = append(connStr, fmt.Sprintf("%s:%s@tcp(%s%s)/%s?parseTime=true",
			info.Username, info.Password, info.Host, portStr, info.Database))
		log.Infof("DB: Connection string: ****:****@tcp(%s%s)/%s?parseTime=true",
			info.Host, portStr, info.Database)
		connStr = append(connStr, fmt.Sprintf("%s:%s@unix(/var/run/mysqld/mysqld.sock)/%s?parseTime=true",
			info.Username, info.Password, info.Database))
		log.Infof("DB: Connection string: ****:****@unix(/var/run/mysqld/mysqld.sock))/%s?parseTime=true",
			info.Database)
		connStr = append(connStr, fmt.Sprintf("%s:%s@unix(/tmp/mysqld.sock)/%s?parseTime=true",
			info.Username, info.Password, info.Database))
		log.Infof("DB: Connection string: ****:****@unix(/tmp/mysqld.sock))/%s?parseTime=true",
			info.Database)
	}
	return connStr
}

// Connect connects to the appropriate DB (mutating dbStore's state with
// the connection information), or returns an error.
func (dbStore *DbStore) Connect() error {
	return dbStore.connectDB()
}

// CreateSchema creates the schema in this DB. If force flag
// is specified, the schema is dropped and recreated.
func (dbStore *DbStore) CreateSchema(force bool) error {
	f := dbStore.createSchemaFuncs[dbStore.Config.Type]
	if f == nil {
		return errors.New(fmt.Sprintf("Unable to create schema for %s", dbStore.Config.Type))
	}
	return f(dbStore, force)
}

// RdbmsStore is to be a full implementation of DbStore including implementing
// ServiceStore interface. Eventually to lead to collapse of DbStore and RdbmsStore
// into one and removal of ServiceStore interface, having one single store for all services.
type RdbmsStore struct {
	common.ServiceStore
	DbStore
}

// policyDb represents how common.Policy is stored in the database.
// For now to keep it simple, it will not be fully normalized --
// we will just keep an ID and policy document as JSON
type PolicyDb struct {
	ID uint64 `sql:"AUTO_INCREMENT"`
	// Policy document as JSON
	Policy       string         `sql:"type:TEXT"`
	ExternalID   sql.NullString `json:"external_id,omitempty" sql:"unique"`
	DatacenterID string
	// DeletedAt is for using soft delete functionality
	// from http://jinzhu.me/gorm/curd.html#delete
	DeletedAt *time.Time
	//	Comment string `gorm:"type:varchar(8192)"`
}

// Name specifies a nicer-looking table name.
func (PolicyDb) TableName() string {
	return "policies"
}

// Entities is to implement ServiceStore.Entities()
func (rdbms *RdbmsStore) Entities() []interface{} {
	retval := make([]interface{}, 0)
	retval = append(retval, &common.Host{})
	retval = append(retval, &common.Datacenter{})
	retval = append(retval, &common.Tenant{})
	retval = append(retval, &common.Segment{})
	retval = append(retval, &common.IPAMEndpoint{})

	// TODO this table used by romana agent
	// in local sqlite3 database the structure
	// has no business doing here and resulting
	// tables has no business showing up
	// in all other databases. That store must
	// be deprecated asap or it's going to cause pain.
	// Stas.
	retval = append(retval, &common.IPtablesRule{})
	retval = append(retval, &PolicyDb{})
	return retval
}

func (rdbms *RdbmsStore) CreateSchemaPostProcess() error {
	db := rdbms.DbStore.Db
	db.Model(&common.Tenant{}).AddUniqueIndex("idx_extid", "external_id")
	db.Model(&common.Segment{}).AddUniqueIndex("idx_tenant_name_extid", "tenant_id", "name", "external_id")

	db.Model(&common.IPAMEndpoint{}).AddUniqueIndex("idx_tenant_segment_host_network_id", "tenant_id", "segment_id", "host_id", "network_id")
	db.Model(&common.IPAMEndpoint{}).AddUniqueIndex("idx_ip", "ip")

	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

// AddHost adds a new host. It also makes sure
// that if a Romana CIDR is not assigned, then to create and assign a new
// romana cidr using help of helper functions like findFirstAvaiableID
// and getNetworkFromID.
func (rdbms *RdbmsStore) AddHost(dc common.Datacenter, host *common.Host) error {
	var err error
	romanaIP := strings.TrimSpace(host.RomanaIp)
	if romanaIP == "" {
		tx := rdbms.DbStore.Db.Begin()
		var allHostsID []uint64
		if err := tx.Table("hosts").Pluck("id", &allHostsID).Error; err != nil {
			tx.Rollback()
			return err
		}

		id := findFirstAvaiableID(allHostsID)
		host.RomanaIp, err = getNetworkFromID(id, dc.PortBits, dc.Cidr)
		// TODO: auto generation of romana cidr doesn't handle previously
		//       allocated cidrs currently, thus it needs to be handled
		//       here so that no 2 hosts get same or overlapping cidrs.
		//       here check needs to be in place to detect all manually
		//       inserted romana cidrs for overlap.
		if err != nil {
			tx.Rollback()
			return err
		}

		if err = tx.Create(host).Error; err != nil {
			tx.Rollback()
			return err
		}
		tx.Commit()
	} else {
		// TODO: auto generation of romana cidr doesn't handle previously
		//       allocated cidrs currently, thus it needs to be handled
		//       here so that no 2 hosts get same or overlapping cidrs.
		//       here check needs to be in place that auto generated cidrs
		//       overlap with this manually assigned one or not.
		rdbms.DbStore.Db.NewRecord(*host)
		db := rdbms.DbStore.Db.Create(host)
		if err = common.GetDbErrors(db); err != nil {
			log.Printf("topology.store.addHost(%v): %v", host, err)
			return err
		}
	}
	if err != nil {
		return err
	}
	log.Println("Sucessfully added host(", host, ").")
	return nil
}

// DeleteHost is currently not implemented.
func (rdbms *RdbmsStore) DeleteHost(hostID uint64) error {
	// This never was implemented in the RDBMS version...
	return common.NewError("Unimplemented: DeleteHost")
}

// ListHosts implements ListHosts method of Store interface
func (rdbms *RdbmsStore) ListHosts() ([]common.Host, error) {
	var hosts []common.Host
	rdbms.DbStore.Db.Find(&hosts)
	err := common.MakeMultiError(rdbms.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

// FindHost implements FindHost method of Store interface
func (rdbms *RdbmsStore) GetHost(hostID uint64) (common.Host, error) {
	host := common.Host{}
	rdbms.DbStore.Db.Where("id = ?", hostID).First(&host)
	err := common.MakeMultiError(rdbms.DbStore.Db.GetErrors())
	if err != nil {
		return host, err
	}
	return host, nil
}
