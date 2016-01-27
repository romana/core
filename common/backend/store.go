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

package common

import (
	"github.com/jinzhu/gorm"
	"log"
)

// MultiError adapts GORM (ORM - see https://github.com/jinzhu/gorm) array of errors found in GetErrors()
// to a single error interface.
// GORMdoes not return errors at every turn. It accumulates them and returns
// them whenever you feel like calling GetErrors() (https://godoc.org/github.com/jinzhu/gorm#DB.GetErrors).
// Since this is not consistent  with the rest of the code, I prefer to isolate it
// here and make an adapter.
type MultiError struct {
	errors []error
}

func MakeMultiError(errors []error) error {
	if errors == nil {

		return nil
	}
	if len(errors) == 0 {

		return nil
	}

	return &MultiError{errors}
}

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

// Stores information needed for a DB connection.
type StoreConfig struct {
	Host     string
	Port     uint64
	Username string
	Password string
	Database string
}

func MakeStoreConfig(configMap map[string]interface{}) StoreConfig {
	storeConfig := StoreConfig{}
	storeConfig.Host = configMap["host"].(string)

	if storeConfig["port"] != nil {
		portStr := storeConfig["port"].(string)
		port, err := strconv.ParseUint(portStr, 10, 64)
		if err != nil {
			log.Printf("Error parsing %s", portStr)
		} else {
			info.Port = port
		}
	}
	storeConfig.Username = storeConfig["username"].(string)
	storeConfig.Password = storeConfig["password"].(string)
	storeConfig.Database = storeConfig["database"].(string)
	return storeConfig
}

// Defines generic store interface that can be used
// by any service for persistence.
type Store interface {
	SetConfig(config StoreConfig) error
	Connect() error
}

type GormStore interface {
	DB() *gorm.DB
}

