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
	root Root
}

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (rootStore *rootStore) CreateSchemaPostProcess() error {
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

// Entities implements Entities method of
// Service interface.
func (rootStore *rootStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = &User{}
	retval[1] = &Role{}
	return retval
}

type User struct {
	Id       uint64 `sql:"AUTO_INCREMENT" json:"id"`
	Username string `json:"username"`
	Roles    []Role `gorm:"many2many:user_roles;"`
	Password string `json:"password"`
}

type Role struct {
	Id   uint64 `sql:"AUTO_INCREMENT" json:"id"`
	Name string `json:"naame"`
}

// Authenticate returns a list of roles this credential
// has or an error if cannot authenticate.
func (rootStore *rootStore) Authenticate(cred common.Credential) ([]common.Role, error) {
	rootServiceConfig := rootStore.root.config.full.Services[rootStore.root.Name()]
	if rootServiceConfig.ServiceSpecific["auth"] != "yes" {
		log.Println("Authentication is disabled")
		return nil, nil
	} else {
		log.Println("Authentication is enabled")
		gormDb := rootStore.DbStore.Db
		whereClause = fmt.Sprintf("username = ? AND password = %s", rootStore.DbStore.GetPasswordFunction())
		var roles []common.Role
		gormDb.Table("role").Select("role.name").Joins("JOIN user_roles ON role.id = user_roles.role_id JOIN users ON users.id = user_roles.user_id").Where(whereClause, cred.Username, cred.Password).Find(roles)
		err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
		if err != nil {
			return nil, err
		}
		return roles, nil
	}
}
