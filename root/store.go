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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
package root

import (
	"fmt"
	//	"github.com/jinzhu/gorm"

	_ "github.com/go-sql-driver/mysql"
	"github.com/romana/core/common"
)

type rootStore struct {
	common.DbStore
}

func (rootStore rootStore) CreateSchemaPostProcess() error {
	passwd, err := rootStore.GetPasswordFunction()
	if err != nil {
		return err
	}
	sql := fmt.Sprintf("INSERT INTO users (username, password) VALUES (?, %s)", passwd)
	rootStore.DbStore.Db.Exec(sql, "admin", "password")
	return common.MakeMultiError(rootStore.DbStore.Db.GetErrors())
}

func (rootStore *rootStore) Entities() []interface{} {
	retval := make([]interface{}, 1)
	retval[0] = User{}
	return retval
}

type User struct {
	Id       uint64 `sql:"AUTO_INCREMENT" json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}
