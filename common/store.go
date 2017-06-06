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
	"github.com/go-sql-driver/mysql"
	"github.com/mattn/go-sqlite3"
	log "github.com/romana/rlog"
	"net/http"
	"net/url"
	"strconv"
)

// StoreConfig stores information needed for a connection to backing store.
// It is just a typed collection of all possible required parameters, a
// superset of them.
type StoreConfig struct {
	// TODO to accommodate distributed stores, this should be changed to
	// []Address. For now we'll just use single one.
	Host     string
	Port     uint64
	Username string
	Password string
	// Database doubles as:
	// - File name for sqlite
	// - Prefix for etcd
	Database string
	// Database type (one of SupportedStoreTypes)
	Type string
}

const (
	MySQLUniqueConstraintErrorCode = 1062
	StoreTypeMysql                 = "mysql"
	StoreTypeSqlite3               = "sqlite3"
	StoreTypeEtcd                  = "etcd"
)

var SupportedStoreTypes []string

func init() {
	SupportedStoreTypes = []string{StoreTypeMysql, StoreTypeSqlite3, StoreTypeEtcd}
}

func (sc StoreConfig) String() string {
	return fmt.Sprintf("Host: %s, Port: %d, Username: ****, Password: ****, Database: %s, Type: %s",
		sc.Host, sc.Port, sc.Database, sc.Type)
}

// MakeStoreConfig creates StoreConfig object from a map.
func MakeStoreConfig(configMap map[string]interface{}) (StoreConfig, error) {
	storeConfig := StoreConfig{}
	storeConfig.Type = configMap["type"].(string)
	if !In(storeConfig.Type, SupportedStoreTypes) {
		return storeConfig, NewError("Unsupported store format %s", storeConfig.Type)
	}
	if configMap["host"] != nil {
		storeConfig.Host = configMap["host"].(string)
	}
	var err error
	if configMap["port"] != nil {
		var port uint64
		portObj := configMap["port"]
		switch portObj := portObj.(type) {
		case string:
			port, err = strconv.ParseUint(portObj, 10, 64)
			if err != nil {
				return storeConfig, errors.New(fmt.Sprintf("Error parsing port %s", portObj))
			}
		case float64:
			port = uint64(portObj)
		case int:
			port = uint64(portObj)
		default:
			return storeConfig, NewError("Error parsing port %v (of type %T)", portObj, portObj)
		}
		if port != 0 {
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
	return storeConfig, nil
}

// Store defines generic store interface that can be used
// by any service for persistence.
type Store interface {
	// SetConfig sets the configuration
	SetConfig(StoreConfig) error
	// Connect connects to the store
	Connect() error
	// Create the schema, dropping existing one if the force flag is specified
	CreateSchema(bool) error
	// Find finds entries in the store based on the query string. The meaning of the
	// flags is as follows:
	// 1. FindFirst - the first entity (as ordered by primary key) is returned.
	// 2. FindLast - tha last entity is returned
	// 3. FindExactlyOne - it is expected that only one result is to be found --
	// multiple results will yield an errror.
	// 4. FindAll - returns all.
	// Here "entities" *must* be a pointer to an array
	// of entities to find (for example, it has to be &[]Tenant{}, not Tenant{}).
	Find(query url.Values, entities interface{}, flag FindFlag) (interface{}, error)
}

// ServiceStore interface is what each service's store needs to implement.
type ServiceStore interface {
	// Entities returns list of entities (DB tables) this store is managing.
	Entities() []interface{}
	// CreateSchemaPostProcess runs whatever required post-processing after
	// schema creation (perhaps initializing DB with some initial or sample data).
	CreateSchemaPostProcess() error
}

// DbToHttpError produces an appropriate HttpError given an error, if it can
// (for example, producing a 409 CONFLICT in case of a unique or primary key
// constraint violation). If it cannot, it returns the original error.
func DbToHttpError(err error) error {
	switch err := err.(type) {
	case sqlite3.Error:
		if err.Code == sqlite3.ErrConstraint {
			if err.ExtendedCode == sqlite3.ErrConstraintUnique || err.ExtendedCode == sqlite3.ErrConstraintPrimaryKey {
				log.Infof("Error: %s", err)
				return HttpError{StatusCode: http.StatusConflict}
			}
		} else if err.Code == sqlite3.ErrCantOpen {
			log.Infof("Cannot open database file.")
			return NewError500("Database error.")
		}
		log.Infof("DbToHttpError(): Unknown sqlite3 error: %d|%d|%s", err.Code, err.ExtendedCode, err.Error())
		return err
	case *mysql.MySQLError:
		if err.Number == MySQLUniqueConstraintErrorCode {
			log.Infof("Error: %s", err)
			return HttpError{StatusCode: http.StatusConflict}
		}
		log.Infof("DbToHttpError(): Unknown MySQL error: %d %s", err.Number, err.Message)
		return err
	default:
		log.Infof("DbToHttpError(): Unknown error: [%T] %+v", err, err)
		return err
	}
}
