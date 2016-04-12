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
	"encoding/hex"
	"errors"
	"log"

	"github.com/romana/core/common"

	"github.com/pborman/uuid"
)

// Backing store
type tenantStore struct {
	common.DbStore
}

// Entities implements Entities method of
// Service interface.
func (tenantStore *tenantStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = &Tenant{}
	retval[1] = &Segment{}
	return retval
}

type Tenant struct {
	ID         uint64 `sql:"AUTO_INCREMENT"`
	ExternalID string `sql:"not null;unique"`
	Name       string
	Segments   []Segment
	Seq        uint64
}

type Segment struct {
	Id       uint64 `sql:"AUTO_INCREMENT"`
	TenantId uint64
	Name     string
	Seq      uint64
}

func (tenantStore *tenantStore) listTenants() ([]Tenant, error) {
	var tenants []Tenant
	log.Println("In listTenants()", &tenants)
	tenantStore.DbStore.Db.Find(&tenants)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println(tenants)
	return tenants, nil
}

func (tenantStore *tenantStore) listSegments(tenantId uint64) ([]Segment, error) {
	var segments []Segment
	log.Println("In listSegments()", &segments)
	tenantStore.DbStore.Db.Where("tenant_id = ?", tenantId).Find(&segments)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println(segments)
	return segments, nil
}

func (tenantStore *tenantStore) addTenant(tenant *Tenant) error {
	log.Println("In tenantStore addTenant().")

	var tenants []Tenant
	tenantStore.DbStore.Db.Find(&tenants)

	// Most UUID generators return UUID or "". If uuid
	// is invalid i.e len != 32, it should be rejected.
	// Create new UUID in case one is not provided so
	// that db is sane for all platforms.
	if len(tenant.ExternalID) != 32 {
		tenant.ExternalID = hex.EncodeToString(uuid.NewRandom())
	}

	tenant.Seq = uint64(len(tenants) + 1)
	db := tenantStore.DbStore.Db.Create(tenant)
	if db.Error != nil {
		return db.Error
	}
	tenantStore.DbStore.Db.NewRecord(*tenant)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}

func (tenantStore *tenantStore) findTenant(id uint64, uuid string) (Tenant, error) {
	var tenants []Tenant
	log.Println("In findTenant()")
	tenantStore.DbStore.Db.Find(&tenants)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return Tenant{}, err
	}

	for i := range tenants {
		if tenants[i].ID == id || tenants[i].ExternalID == uuid {
			return tenants[i], nil
		}
	}
	// TODO make this a 404
	return Tenant{}, errors.New("Not found")
}

func (tenantStore *tenantStore) addSegment(tenantId uint64, segment *Segment) error {
	var err error

	// TODO(gg): better way of getting sequence
	var segments []Segment
	tenantStore.DbStore.Db.Where("tenant_id = ?", tenantId).Find(&segments)
	segment.Seq = uint64(len(segments) + 1)
	tenantStore.DbStore.Db.NewRecord(*segment)
	segment.TenantId = tenantId
	db := tenantStore.DbStore.Db.Create(segment)
	if db.Error != nil {
		return db.Error
	}

	err = common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (tenantStore *tenantStore) CreateSchemaPostProcess() error {
	return nil
}

func (tenantStore *tenantStore) findSegment(tenantId uint64, id uint64) (Segment, error) {
	var segments []Segment
	log.Println("In findSegment()")
	tenantStore.DbStore.Db.Where("tenant_id = ?", tenantId).Find(&segments)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return Segment{}, err
	}
	for i := range segments {
		if segments[i].Id == id {
			return segments[i], nil
		}
	}
	return Segment{}, errors.New("Not found")
}
