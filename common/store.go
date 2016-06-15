// Copyright (c) 2016 Pani Networks
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

// Contains general routines and definitions for a generic back-end storage
// (currently geared towards RDBMS but not necessarily limited to that).
package common

import (
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
)

// StoreConfig stores information needed for a DB connection.
type StoreConfig struct {
	Host     string
	Port     uint64
	Username string
	Password string
	Database string
	// Database type, e.g., sqlite3, mysql, etc.
	// TODO add a set of constants for it.
	Type string
}

// MakeStoreConfig creates StoreConfig object from a map.
func makeStoreConfig(configMap map[string]interface{}) StoreConfig {
	storeConfig := StoreConfig{}
	storeConfig.Type = configMap["type"].(string)
	if configMap["host"] != nil {
		storeConfig.Host = configMap["host"].(string)
	}
	if configMap["port"] != nil {
		portStr := configMap["port"].(string)
		port, err := strconv.ParseUint(portStr, 10, 64)
		if err != nil {
			log.Printf("Error parsing %s", portStr)
		} else {
			storeConfig.Port = port
		}
	}
	if configMap["username"] != nil {
		storeConfig.Username = configMap["username"].(string)
	}
	if configMap["password"] != nil {
		storeConfig.Password = configMap["password"].(string)
	}
	storeConfig.Database = configMap["database"].(string)
	return storeConfig
}

// Store defines generic store interface that can be used
// by any service for persistence.
type Store interface {
	// SetConfig sets the configuration
	SetConfig(map[string]interface{}) error
	// Connect connects to the store
	Connect() error
	// Create the schema, dropping existing one if the force flag is specified
	CreateSchema(bool) error
	// Find finds all entries in the store based on the query string. If
	// single is specified then it is expected that only one result is to be found --
	// multiple results will yield an errror. Here "entities" *must* be a pointer to an array
	// of entities to find (for example, it has to be &[]Tenant{}, not Tenant{}).
	Find(query url.Values, entities interface{}, single bool) (interface{}, error)
}

// ServiceStore interface is what each service's store needs to implement.
type ServiceStore interface {
	// Entities returns list of entities (DB tables) this store is managing.
	Entities() []interface{}
	// CreateSchemaPostProcess runs whatever required post-processing after
	// schema creation (perhaps initializing DB with some initial or sample data).
	CreateSchemaPostProcess() error
}

// createSchema is a type for functions that create database schemas.
// By defining a type we can more easily store references to functions of
// the specified signature.
type createSchema func(dbStore *DbStore, force bool) error

// DbStore is a structure storing information specific to RDBMS-based
// implementation of Store.
type DbStore struct {
	ServiceStore      ServiceStore
	Config            *StoreConfig
	Db                *gorm.DB
	createSchemaFuncs map[string]createSchema
}

// Find generically implements Find() of store interface.
func (dbStore *DbStore) Find(query url.Values, entities interface{}, single bool) (interface{}, error) {
	queryStringFieldToDbField := make(map[string]string)

	t := reflect.TypeOf(entities).Elem().Elem()
	for i := 0; i < t.NumField(); i++ {
		structField := t.Field(i)
		fieldTag := structField.Tag
		fieldName := structField.Name

		queryStringField := strings.ToLower(fieldName)
		dbField := strings.ToLower(fieldName)
		if fieldTag == "" {
			// If there is no tag, then query variable is just the same as
			// the fieldName...
			log.Printf("No tag for %s", fieldName)
		} else {
			jTag := fieldTag.Get("json")
			if jTag == "" {
				log.Printf("No JSON tag for %s", fieldName)
			} else {
				queryStringField = jTag
			}
			gormTag := fieldTag.Get("gorm")
			log.Printf("Gorm tag for %s: %s (%v)", fieldName, gormTag, fieldTag)
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
							return nil, NewError400(fmt.Sprintf("Expected 2 elements in %s (in %s)", gormVal, gormTag))
						}
						dbField = elts[1]
						break
					}

				}
			}
		}
		log.Printf("Query string field %s, struct field %s, DB field %s", queryStringField, fieldName, dbField)
		queryStringFieldToDbField[queryStringField] = dbField
	}
	log.Printf("%#v", queryStringFieldToDbField)
	whereMap := make(map[string]interface{})

	for k, v := range query {
		k = strings.ToLower(k)
		dbFieldName := queryStringFieldToDbField[k]
		if dbFieldName == "" {
			return nil, NewError400(fmt.Sprintf("Unknown field %s in %v", k, t))
		}
		if len(v) > 1 {
			return nil, NewError400("Did not expect multiple values in " + k)
		}
		whereMap[dbFieldName] = v[0]
	}

	log.Printf("Querying with %#v - %T", whereMap, entities)

	db := dbStore.Db.Where(whereMap).Find(entities)
	err := GetDbErrors(db)
	if err != nil {
		return nil, err
	}
	rowCount := reflect.ValueOf(entities).Elem().Len()

	if rowCount == 0 {
		return nil, NewError404(t.String(), fmt.Sprintf("%#v", whereMap))
	}

	if single {
		if rowCount == 1 {
			return reflect.ValueOf(entities).Elem().Index(0).Interface(), nil
		} else {
			return nil, NewError500(fmt.Sprintf("Multiple results found for %#v", query))
		}
	}

	return entities, nil
}

// SetConfig sets the config object from a map.
func (dbStore *DbStore) SetConfig(configMap map[string]interface{}) error {
	config := makeStoreConfig(configMap)
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

// getConnString returns the appropriate GORM connection string for
// the given DB.
func (dbStore *DbStore) getConnString() string {
	var connStr string
	info := dbStore.Config
	switch info.Type {
	case "sqlite3":
		connStr = info.Database
	default:
		portStr := fmt.Sprintf(":%d", info.Port)
		if info.Port == 0 {
			portStr = ":3306"
		}
		connStr = fmt.Sprintf("%s:%s@tcp(%s%s)/%s?parseTime=true", info.Username, info.Password, info.Host, portStr, info.Database)
	}
	log.Printf("DB: Connection string: %s", connStr)
	return connStr
}

// Connect connects to the appropriate DB (mutating dbStore's state with
// the connection information), or returns an error.
func (dbStore *DbStore) Connect() error {
	if dbStore.Config == nil {
		return errors.New("No configuration specified.")
	}
	connStr := dbStore.getConnString()
	log.Printf("DB: Connecting to %s", connStr)
	db, err := gorm.Open(dbStore.Config.Type, connStr)
	if err != nil {
		return err
	}
	dbStore.Db = &db
	return nil
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

// createSchemaMysql creates schema for a sqlite3 db
func createSchemaSqlite3(dbStore *DbStore, force bool) error {
	log.Println("Entering createSchemaSqlite3()")
	var err error
	schemaName := dbStore.Config.Database
	if force {
		finfo, err := os.Stat(schemaName)
		exist := finfo != nil || os.IsExist(err)
		log.Printf("Before attempting to drop %s, exists: %t, stat: [%v] ... [%v]", schemaName, exist, finfo, err)
		if exist {
			err = os.Remove(schemaName)
			if err != nil {
				return err
			}

		}
	}
	err = dbStore.Connect()
	if err != nil {
		return err
	}

	entities := dbStore.ServiceStore.Entities()
	log.Printf("Creating tables for %v", entities)
	for _, entity := range entities {
		log.Printf("sqlite3: Creating table for %T", entity)
		db := dbStore.Db.CreateTable(entity)
		if db.Error != nil {
			return db.Error
		}
	}

	errs := dbStore.Db.GetErrors()
	log.Println("sqlite3: Errors", errs)
	err2 := MakeMultiError(errs)

	if err2 != nil {
		return err2
	}
	return dbStore.ServiceStore.CreateSchemaPostProcess()
}

// createSchemaMysql creates schema for a MySQL db
func createSchemaMysql(dbStore *DbStore, force bool) error {
	log.Println("in createSchema(", force, ")")

	schemaName := dbStore.Config.Database
	dbStore.Config.Database = "mysql"
	connStr := dbStore.getConnString()
	log.Printf("DB: Connecting to %s", connStr)
	db, err := gorm.Open("mysql", connStr)

	if err != nil {
		return err
	}
	var sql string

	if force {
		sql = fmt.Sprintf("DROP DATABASE IF EXISTS %s", schemaName)
		db.Exec(sql)
	}

	sql = fmt.Sprintf("CREATE DATABASE %s", schemaName)
	db.Exec(sql)
	err = MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}

	dbStore.Config.Database = schemaName
	err = dbStore.Connect()
	if err != nil {
		return err
	}

	entities := dbStore.ServiceStore.Entities()

	for i := range entities {
		entity := entities[i]
		db := dbStore.Db.CreateTable(entity)
		if db.Error != nil {
			return db.Error
		}
	}

	err = MakeMultiError(dbStore.Db.GetErrors())
	if err != nil {
		return err
	}
	return dbStore.ServiceStore.CreateSchemaPostProcess()
}
