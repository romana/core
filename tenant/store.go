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
	"github.com/romana/core/common"
	"log"

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
	t := Tenant{}
	retval[0] = &t
	s := Segment{}
	retval[1] = &s
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
	ID         uint64 `sql:"AUTO_INCREMENT"`
	ExternalID string `sql:"not null;"`
	TenantID   uint64
	Name       string
	Seq        uint64
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

// listSegments returns a list of segments for a specific tenant
// whose tenantId is specified.
func (tenantStore *tenantStore) listSegments(tenantId string) ([]Segment, error) {
	var segments []Segment
	log.Println("In listSegments()", &segments)
	db := tenantStore.DbStore.Db.Joins("JOIN tenants ON segments.tenant_id = tenants.id").
		Where("tenants.id = ? OR tenants.external_id = ?", tenantId, tenantId).
		Find(&segments)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return segments, nil
}

func (tenantStore *tenantStore) addTenant(tenant *Tenant) error {
	log.Println("In tenantStore addTenant().")

	var tenants []Tenant
	tenantStore.DbStore.Db.Find(&tenants)

	if tenant.ExternalID == "" {
		tenant.ExternalID = hex.EncodeToString(uuid.NewRandom())
	}

	tenant.Seq = uint64(len(tenants) + 1)
	db := tenantStore.DbStore.Db
	tenantStore.DbStore.Db.Create(tenant)
	if db.Error != nil {
		return db.Error
	}
	tenantStore.DbStore.Db.NewRecord(*tenant)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}
	return nil
}

func (tenantStore *tenantStore) findTenants(id string) ([]Tenant, error) {
	var tenants []Tenant
	log.Println("In findTenant()")
	db := tenantStore.DbStore.Db.Where("id = ? OR external_id = ?", id, id).Find(&tenants)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return tenants, nil
}

func (tenantStore *tenantStore) findTenantsByName(name string) ([]Tenant, error) {
	var tenants []Tenant
	log.Println("In findTenant()")
	db := tenantStore.DbStore.Db.Find(&tenants).Where("name = ?", name)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	if len(tenants) == 0 {
		return nil, common.NewError404("tenant", name)
	}
	return tenants, nil
}

func (tenantStore *tenantStore) addSegment(tenantId uint64, segment *Segment) error {
	var err error

	// TODO(gg): better way of getting sequence
	var segments []Segment
	db := tenantStore.DbStore.Db.Where("tenant_id = ?", tenantId).Find(&segments)
	err = common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}
	segment.Seq = uint64(len(segments) + 1)

	if segment.ExternalID == "" {
		segment.ExternalID = hex.EncodeToString(uuid.NewRandom())
	}

	tenantStore.DbStore.Db.NewRecord(*segment)
	err = common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}

	if db.Error != nil {
		return db.Error
	}

	segment.TenantID = tenantId
	db = tenantStore.DbStore.Db.Create(segment)
	if db.Error != nil {
		return db.Error
	}

	err = common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}

	if db.Error != nil {
		return db.Error
	}
	return nil
}

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (tenantStore *tenantStore) CreateSchemaPostProcess() error {
	db := tenantStore.Db
	log.Printf("tenantStore.CreateSchemaPostProcess(), DB is %v", db)
	db.Model(&Segment{}).AddUniqueIndex("idx_tenant_segment_extid", "tenant_id", "external_id")
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}

func (tenantStore *tenantStore) findSegments(tenantId string, segmentId string) ([]Segment, error) {
	var segments []Segment
	log.Println("In findSegment()")
	// TODO should internal ID take precedence?
	db := tenantStore.DbStore.Db.Joins("JOIN tenants ON segments.tenant_id = tenants.id").
		Where("(tenants.id = ? OR tenants.external_id = ?) AND (segments.id = ? OR segments.external_id = ?)", tenantId, tenantId, segmentId, segmentId).
		Find(&segments)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}

	if db.Error != nil {
		return nil, db.Error
	}
	return segments, nil
}
