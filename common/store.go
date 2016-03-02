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
	"os"
	"strconv"
)

// MultiError adapts GORM (ORM - see https://github.com/jinzhu/gorm) array of errors found in GetErrors()
// to a single error interface.
// GORM does not return errors at every turn. It accumulates them and returns
// them whenever you feel like calling GetErrors() (https://godoc.org/github.com/jinzhu/gorm#DB.GetErrors).
// Since this is not consistent with the rest of the code, I prefer to isolate it
// here and make an adapter.
type MultiError struct {
	errors []error
}

// MakeMultiError creates a single MultiError (or nil!) out of an array of
// error objects.
func MakeMultiError(errors []error) error {
	if errors == nil {
		return nil
	}
	if len(errors) == 0 {
		return nil
	}

	return &MultiError{errors}
}

// Error satisfies Error method on error interface and returns
// a concatenated string of all error messages.
func (m *MultiError) Error() string {
	s := ""
	for i := range m.errors {
		if len(s) > 0 {
			s += "; "
		}
		s += m.errors[i].Error()
	}
	return s
}

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
	SetConfig(configMap map[string]interface{}) error
	// Connect connects to the store
	Connect() error
	// Create the schema, dropping existing one if the force flag is specified
	CreateSchema(force bool) error
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
type createSchema func(dbStore DbStore, force bool) error

// DbStore is a structure storing information specific to RDBMS-based
// implementation of Store.
type DbStore struct {
	ServiceStore      ServiceStore
	Config            *StoreConfig
	Db                *gorm.DB
	createSchemaFuncs map[string]createSchema
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
		connStr = fmt.Sprintf("%s:%s@tcp(%s%s)/%s", info.Username, info.Password, info.Host, portStr, info.Database)
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
	return f(*dbStore, force)
}

// createSchemaMysql creates schema for a sqlite3 db
func createSchemaSqlite3(dbStore DbStore, force bool) error {
	var err error
	schemaName := dbStore.Config.Database
	if force {
		_, err := os.Stat(schemaName)
		if os.IsExist(err) {
			err = os.Remove(schemaName)
			if err != nil {
				return err
			}
		}
	}
	connStr := dbStore.getConnString()
	log.Printf("DB: Connecting to %s", connStr)
	db, err := gorm.Open("sqlite3", connStr)

	if err != nil {
		return err
	}

	entities := dbStore.ServiceStore.Entities()
	for _, entity := range entities {
		db.CreateTable(entity)
	}

	errs := db.GetErrors()
	log.Println("Errors", errs)
	err2 := MakeMultiError(errs)

	if err2 != nil {
		return err2
	}
	return dbStore.ServiceStore.CreateSchemaPostProcess()
}

// createSchemaMysql creates schema for a MySQL db
func createSchemaMysql(dbStore DbStore, force bool) error {
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

	dbStore.Config.Database = schemaName
	err = dbStore.Connect()
	if err != nil {
		return err
	}

	entities := dbStore.ServiceStore.Entities()
	for i := range entities {
		entity := entities[i]
		db.CreateTable(entity)
	}

	errs := db.GetErrors()
	log.Println("Errors", errs)
	err2 := MakeMultiError(errs)

	if err2 != nil {
		return err2
	}
	return dbStore.ServiceStore.CreateSchemaPostProcess()
}
