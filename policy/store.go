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
package policy

import (
	"encoding/json"

	_ "github.com/go-sql-driver/mysql"
	"github.com/romana/core/common"
	"log"
	"time"
)

type policyStore struct {
	common.DbStore
}

func (policyStore *policyStore) addPolicy(policyDoc *common.Policy) error {
	json, err := json.Marshal(policyDoc)
	policyDb := &PolicyDb{}
	policyDb.Policy = string(json)
	db := policyStore.DbStore.Db
	db.Create(policyDb)
	err = common.GetDbErrors(db)
	if err != nil {
		return err
	}
	db.NewRecord(*policyDb)
	err = common.GetDbErrors(db)
	if err != nil {
		return err
	}
	policyDoc.ID = policyDb.ID
	log.Printf("addPolicy(): Stored %s with ID %d", policyDoc.Name, policyDb.ID)
	return nil
}

func (policyStore *policyStore) listPolicies() ([]common.Policy, error) {
	var policyDb []PolicyDb
	var policies []common.Policy
	db := policyStore.DbStore.Db.Find(&policyDb)
	err := common.GetDbErrors(db)
	policies = make([]common.Policy, len(policyDb))
	for i, p := range policyDb {
		json.Unmarshal([]byte(p.Policy), &policies[i])
	}
	return policies, err
}

func (policyStore *policyStore) getPolicy(id uint64) (common.Policy, error) {
	policyDoc := common.Policy{}
	db := policyStore.DbStore.Db.Where("id = ?", id).First(&policyDoc)
	err := common.GetDbErrors(db)
	return policyDoc, err
}

// inactivatePolicy marks policy as inactive. This is done
// upon receiving a DELETE request but before distributing
// this request to agents.
func (policyStore *policyStore) inactivatePolicy(id uint64) error {
	policyDb := &PolicyDb{}
	db := policyStore.DbStore.Db
	db = db.Where("id = ?", id).Delete(policyDb)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
	//	tx := db.Begin()
	//	err := common.GetDbErrors(db)
	//	if err != nil {
	//		return err
	//	}
	//
	//	tx = tx.First(policy, "id = ?", id).Find(&policy)
	//	err := common.GetDbErrors(db)
	//	if err != nil {
	//		tx.Rollback()
	//		return err
	//	}
	//	tx = tx.Model(&policy).Update("is_active", false)
	//	if err != nil {
	//		tx.Rollback()
	//		return err
	//	}
	//	tx.Commit()
}

func (policyStore *policyStore) deletePolicy(id uint64) error {
	policyDb := &PolicyDb{}
	db := policyStore.DbStore.Db
	db = db.Unscoped().Where("id = ?", id).Delete(policyDb)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (policyStore *policyStore) CreateSchemaPostProcess() error {
	return nil
}

// policyDb represents how common.Policy is stored in the database.
// For now to keep it simple, it will not be fully normalized --
// we will just keep an ID and policy document as JSON
type PolicyDb struct {
	ID uint64 `sql:"AUTO_INCREMENT"`
	// Policy document as JSON
	Policy string `sql:"TEXT"`
	// DeletedAt is for using soft delete functionality
	// from http://jinzhu.me/gorm/curd.html#delete
	DeletedAt *time.Time
}

// Name specifies a nicer-looking table name.
func (PolicyDb) Name() string {
	return "policy"
}

// Entities implements Entities method of
// Service interface.
func (policyStore *policyStore) Entities() []interface{} {
	retval := make([]interface{}, 1)
	retval[0] = &PolicyDb{}
	return retval
}
