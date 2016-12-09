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
	"database/sql"
	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	"github.com/romana/core/common"
	"github.com/romana/core/common/store"
	"log"
)

type policyStore struct {
	*store.RdbmsStore
}

func (policyStore *policyStore) addPolicy(policyDoc *common.Policy) error {
	// TODO ensure uniqueness of datacenter/external ID combination.
	json, err := json.Marshal(policyDoc)
	if err != nil {
		return err
	}
	policyDb := &store.PolicyDb{}
	policyDb.Policy = string(json)
	if policyDoc.ID != 0 {
		policyDb.ID = policyDoc.ID
	}
	if policyDoc.ExternalID != "" {
		policyDb.ExternalID = sql.NullString{String: policyDoc.ExternalID, Valid: true}
	}
	tx := policyStore.DbStore.Db.Begin()
	err = common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	tx = tx.Create(policyDb)
	err = common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	policyDoc.ID = policyDb.ID
	log.Printf("addPolicy(): Stored %s with ID %d", policyDoc.Name, policyDb.ID)
	return nil
}

func (policyStore *policyStore) listPolicies() ([]common.Policy, error) {
	var policyDb []store.PolicyDb
	var policies []common.Policy
	db := policyStore.DbStore.Db.Find(&policyDb)
	err := common.GetDbErrors(db)
	if err != nil {
		return policies, err
	}
	policies = make([]common.Policy, len(policyDb))
	for i, p := range policyDb {
		json.Unmarshal([]byte(p.Policy), &policies[i])
		policies[i].ID = p.ID
	}
	return policies, err
}

func (policyStore *policyStore) lookupPolicy(externalID string) (uint64, error) {
	policyDbEntry := store.PolicyDb{}
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
	policyDbEntry := store.PolicyDb{}
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
	policyDb := &store.PolicyDb{}
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

// findPolicyByName returns first found policy corresponding to policy
// name provided. Policy names are not unique, thus the return
// value is the first policy found in the list of policies present.
func (policyStore *policyStore) findPolicyByName(name string) (common.Policy, error) {
	var policyDb []store.PolicyDb
	var policies []common.Policy
	log.Println("In findPoliciesByName()")
	db := policyStore.DbStore.Db.Find(&policyDb)
	err := common.GetDbErrors(db)
	if err != nil {
		return common.Policy{}, err
	}
	policies = make([]common.Policy, len(policyDb))
	for i, p := range policyDb {
		err = json.Unmarshal([]byte(p.Policy), &policies[i])
		if err != nil {
			return common.Policy{}, err
		}
		if policies[i].Name == name {
			policies[i].ID = p.ID
			return policies[i], nil
		}
	}
	return common.Policy{}, common.NewError404("policy", name)
}

func (policyStore *policyStore) deletePolicy(id uint64) error {
	policyDb := &store.PolicyDb{}
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
