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

package tenant

import (
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/common/store"
	"log"
	"strconv"
)

// Backing store
type tenantStore struct {
	*store.RdbmsStore
}

func (tenantStore *tenantStore) listTenants() ([]common.Tenant, error) {
	var tenants []common.Tenant
	log.Println("In listTenants()", &tenants)
	tenantStore.RdbmsStore.DbStore.Db.Find(&tenants)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println(tenants)
	return tenants, nil
}

// listSegments returns a list of segments for a specific tenant
// whose tenantId is specified.
func (tenantStore *tenantStore) listSegments(tenantId string) ([]common.Segment, error) {
	var segments []common.Segment

	// Testing tenantId for being an int, if successful
	// match tenants by ID field, otherwise match tenants
	// by an ExternalID.
	var whereClause string
	if _, err := strconv.Atoi(tenantId); err == nil {
		whereClause = "tenants.id = ?"
	} else {
		whereClause = "tenants.external_id = ?"
	}

	db := tenantStore.DbStore.Db.Joins("JOIN tenants ON segments.tenant_id = tenants.id").
		Where(whereClause, tenantId).
		Find(&segments)
	err := common.MakeMultiError(db.GetErrors())
	log.Printf("In listSegments(): %v, %v", segments, err)
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return segments, nil
}

func (tenantStore *tenantStore) addTenant(tenant *common.Tenant) error {
	//	log.Println("In tenantStore addTenant()")
	log.Printf("In tenantStore addTenant(%v) in %s", *tenant, tenantStore.Config.Database)
	var tenants []common.Tenant
	tx := tenantStore.RdbmsStore.DbStore.Db.Begin()
	err := common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	tx = tx.Find(&tenants)
	err = common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	tenant.NetworkID = uint64(len(tenants))

	tx = tx.Create(tenant)
	err = common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

func (tenantStore *tenantStore) addSegment(tenantId uint64, segment *common.Segment) error {
	var err error
	tx := tenantStore.RdbmsStore.DbStore.Db.Begin()

	var segments []common.Segment
	tx = tx.Where("tenant_id = ?", tenantId).Find(&segments)
	err = common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	segment.NetworkID = uint64(len(segments))
	segment.TenantID = tenantId
	tx = tx.Create(segment)
	err = common.GetDbErrors(tx)

	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

func (tenantStore *tenantStore) getTenant(id string) (common.Tenant, error) {
	ten := common.Tenant{}
	var count int
	log.Println("In getTenant()")
	db := tenantStore.RdbmsStore.DbStore.Db.Where("id = ?", id).First(&ten).Count(&count)
	err := common.GetDbErrors(db)
	if err != nil {
		return ten, err
	}
	if count == 0 {
		return ten, common.NewError404("tenant", id)
	}
	return ten, nil
}

func (tenantStore *tenantStore) getSegment(tenantId string, segmentId string) (common.Segment, error) {
	seg := common.Segment{}
	var count int
	db := tenantStore.RdbmsStore.Db.Where("tenant_id = ? AND id = ?", tenantId, segmentId).
		First(&seg).Count(&count)

	err := common.GetDbErrors(db)
	if err != nil {
		return seg, err
	}
	if count == 0 {
		return seg, common.NewError404("segment/tenant", fmt.Sprintf("%s/%s", tenantId, segmentId))
	}
	return seg, nil
}
