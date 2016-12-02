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
	_ "github.com/go-sql-driver/mysql"
	"github.com/romana/core/common"
	log "github.com/romana/rlog"
)

type rootStore struct {
	common.DbStore
	isAuthEnabled bool
}

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (rootStore *rootStore) CreateSchemaPostProcess() error {
	passwd, err := rootStore.GetPasswordFunction()
	if err != nil {
		log.Errorf("Error in root.CreateSchemaPostProcess: %s", err)
		return err
	}
	sql := fmt.Sprintf("INSERT INTO users (username, password) VALUES (?, %s)", passwd)
	rootStore.DbStore.Db.Exec(sql, "admin", "password")
	rootStore.DbStore.Db.Exec(sql, "service", "password")
	rootStore.DbStore.Db.Exec(sql, "tenant1", "password")
	rootStore.DbStore.Db.Exec(sql, "tenant2", "password")
	rootStore.DbStore.Db.Exec("INSERT INTO roles (name) VALUES ('admin'),('service'),('tenant')")
	rootStore.DbStore.Db.Exec("INSERT INTO user_roles (user_user_id,role_id) VALUES (1,1),(2,2),(3,3),(4,3)")
	rootStore.DbStore.Db.Exec("INSERT INTO attributes (attribute_key,attribute_value) VALUES ('tenant','1'),('tenant','2')")
	rootStore.DbStore.Db.Exec("INSERT INTO user_attributes (user_user_id,attribute_id) VALUES (3,1),(4,2)")
	//	rootStore.DbStore.Db.Exec("INSERT INTO roles (name) VALUES (admin)")
	err = common.GetDbErrors(rootStore.DbStore.Db)
	if err != nil {
		log.Errorf("Error in root.CreateSchemaPostProcess: %s", err)
		return err
	}
	return nil
}

// Entities implements Entities method of
// Service interface.
func (rootStore *rootStore) Entities() []interface{} {
	retval := make([]interface{}, 3)
	retval[0] = &common.User{}
	retval[1] = &common.Role{}
	retval[2] = &common.Attribute{}
	return retval
}

// Authenticate returns a list of roles this credential
// has or an error if cannot authenticate.
func (rootStore *rootStore) Authenticate(cred common.Credential) (common.User, error) {
	user := common.User{}
	if !rootStore.isAuthEnabled {
		log.Debugf("Authentication is disabled")
		return common.DefaultAdminUser, nil
	}
	log.Infof("Authentication is enabled")
	gormDb := rootStore.DbStore.Db
	pwdFunc, err := rootStore.DbStore.GetPasswordFunction()
	if err != nil {
		return user, err
	}
	where := fmt.Sprintf("users.username = ? AND users.password = %s", pwdFunc)
	log.Debugf("Looking for %s", cred.Username)
	var roles []common.Role
	sql := fmt.Sprintf(`SELECT roles.name FROM users 
		JOIN user_roles ON users.user_id = user_roles.user_user_id 
		JOIN roles ON user_roles.role_id = roles.id WHERE %s`, where)
	log.Debugf("Executing %s on %s", sql, rootStore.Config.Database)
	gormDb.Raw(sql, cred.Username, cred.Password).Scan(&roles)

	var attributes []common.Attribute
	sql = fmt.Sprintf(`SELECT attributes.attribute_key, 
		attributes.attribute_value FROM users 
		JOIN user_attributes ON users.user_id = user_attributes.user_user_id 
		JOIN attributes ON user_attributes.attribute_id = attributes.id 
		WHERE %s`, where)
	log.Debugf("Executing %s on %s", sql, rootStore.Config.Database)
	gormDb.Raw(sql, cred.Username, cred.Password).Scan(&attributes)
	log.Debugf("For %s, found roles %v and attributes %v", cred.Username, roles, attributes)
	if len(roles) == 0 && len(attributes) == 0 {
		return user, common.NewError403()
	}

	user.Roles = roles
	user.Attributes = attributes
	// We don't want to pass this around.
	user.Username = ""
	user.Password = ""
	err = common.GetDbErrors(rootStore.DbStore.Db)
	if err != nil {
		return user, err
	}
	log.Infof("Found user %+v", user)
	return user, nil

}
