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
	rootStore.DbStore.Db.Exec("INSERT INTO roles (name) VALUES (admin)")
//	rootStore.DbStore.Db.Exec("INSERT INTO roles (name) VALUES (admin)")
	return common.MakeMultiError(rootStore.DbStore.Db.GetErrors())
}

func (rootStore *rootStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = User{}
	retval[1] = Role{}
	return retval
}

type User struct {
	Id       uint64 `sql:"AUTO_INCREMENT" json:"id"`
	Username string `json:"username"`
	Roles []Role  `gorm:"many2many:user_roles;"` 
	Password string `json:"password"`
}

type Role struct {
	Id       uint64 `sql:"AUTO_INCREMENT" json:"id"`
	Name string `json:"naame"`
}


// Authenticate method here fulfills the Authenticate() method of common.AuthDb interface.
// When this rootStore is passed to common.AuthMiddleware middleware, this method will be
// called as a request comes in.
func (rootStore *rootStore) Authenticate(user string, password string) ([]common.Role, error) {
	gormDb := rootStore.DbStore.Db
	whereClause = fmt.Sprintf("username = ? AND password = %s", rootStore.DbStore.GetPasswordFunction())
	var roles []Role
	gormDb.Table("role").Select("role.name").Joins("JOIN user_roles ON role.id = user_roles.role_id JOIN users ON users.id = user_roles.user_id").Where(whereClause, username, password).Find(roles)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return roles, nil
}


db.Joins("JOIN user_roles ON users.id = user_roles.user_id JOIN roleusers on users.id = emails.user_id").Where("users.name = ?", "jinzhu").Find(&emails)