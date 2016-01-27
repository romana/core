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

	"errors"

	_ "github.com/go-sql-driver/mysql"
)

type MysqlStore struct {
	config    StoreConfig
	db      *gorm.DB
}

func (mysqlStore *MysqlStore) DB() *gorm.DB {
	return mysqlStore.db
}


func (mysqlStore *MysqlStore) ValidateConnectionInformation() error {
	return mysqlStore.connect()
}

func (mysqlStore *MysqlStore) getConnString() {
	info := mysqlStore.info
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", info.Username, info.Password, info.Host, info.Port, info.Database)
}

func (mysqlStore *mysqlStore) Connect() error {
	log.Println("in connect(", mysqlStore.connStr, ")")
	if mysqlStore.connStr == "" {
		return errors.New("No connection information.")
	}

	db, err := gorm.Open("mysql", mysqlStore.connStr)
	if err != nil {
		return err
	}
	mysqlStore.db = &db
	return nil
}
