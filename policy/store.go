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
	// TODO ensure uniqueness of datacenter/external ID combination.
	// TODO assume that external ID is taken from name if not specified.
	// At least one must be specified.
	json, err := json.Marshal(policyDoc)
	policyDb := &PolicyDb{}
	policyDb.Policy = string(json)
	policyDb.ExternalID = policyDoc.ExternalID
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
	if err != nil {
		return policies, err
	}
	policies = make([]common.Policy, len(policyDb))
	for i, p := range policyDb {
		json.Unmarshal([]byte(p.Policy), &policies[i])
	}
	return policies, err
}

func (policyStore *policyStore) lookupPolicy(externalID string, dcID uint64) (uint64, error) {
	policyDbEntry := PolicyDb{}
	log.Printf("Looking up policy with id = %s ", externalID)
	db := policyStore.DbStore.Db.First(&policyDbEntry, "external_id = ?", externalID)
	if db.RecordNotFound() {
		return 0, common.NewError404("policy", externalID)
	}
	err := common.GetDbErrors(db)
	// TODO return proper error (404) in case not found.
	if err != nil {
		return 0, err
	}
	return policyDbEntry.ID, nil
}

func (policyStore *policyStore) getPolicy(id uint64, markedDeleted bool) (common.Policy, error) {
	policyDbEntry := PolicyDb{}
	policyDoc := common.Policy{}
	log.Printf("Looking up policy with id = %v (deleted: %v)", id, markedDeleted)
	var err error
	if markedDeleted {
		db := policyStore.DbStore.Db.Unscoped().First(&policyDbEntry, "id = ?", id)
		if db.RecordNotFound() {
			return policyDoc, common.NewError404("policy", string(id))
		}
		err = common.GetDbErrors(db)
	} else {
		db := policyStore.DbStore.Db.First(&policyDbEntry, "id = ?", id)
		if db.RecordNotFound() {
			return policyDoc, common.NewError404("policy", string(id))
		}
		err = common.GetDbErrors(db)
	}
	// TODO return proper error (404) in case not found.
	if err != nil {
		return policyDoc, err
	}
	log.Printf("Found %v, unmarshaling %s", policyDbEntry, policyDbEntry.Policy)
	err = json.Unmarshal([]byte(policyDbEntry.Policy), &policyDoc)
	if err != nil {
		return policyDoc, err
	}
	policyDoc.ID = policyDbEntry.ID
	return policyDoc, err
}

// inactivatePolicy marks policy as inactive. This is done
// upon receiving a DELETE request but before distributing
// this request to agents.
func (policyStore *policyStore) inactivatePolicy(id uint64) error {
	policyDb := &PolicyDb{}
	db := policyStore.DbStore.Db
	db = db.Where("id = ?", id).Delete(policyDb)
	if db.RecordNotFound() {
		return common.NewError404("policy", string(id))
	}
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

func (policyStore *policyStore) deletePolicy(id uint64) error {
	policyDb := &PolicyDb{}
	db := policyStore.DbStore.Db
	db = db.Unscoped().Where("id = ?", id).Delete(policyDb)
	if db.RecordNotFound() {
		return common.NewError404("policy", string(id))
	}
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
	Policy       string `gorm:"type:varchar(8192)"`
	ExternalID   string
	DatacenterID string
	// DeletedAt is for using soft delete functionality
	// from http://jinzhu.me/gorm/curd.html#delete
	DeletedAt *time.Time
	//	Comment string `gorm:"type:varchar(8192)"`
}

// Name specifies a nicer-looking table name.
func (PolicyDb) TableName() string {
	return "policies"
}

// Entities implements Entities method of
// Service interface.
func (policyStore *policyStore) Entities() []interface{} {
	retval := make([]interface{}, 1)
	retval[0] = &PolicyDb{}
	return retval
}
