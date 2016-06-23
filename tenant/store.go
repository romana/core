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
	"log"
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
	ID         uint64    `sql:"AUTO_INCREMENT" json:"id,omitempty"`
	ExternalID string    `sql:"not null" json:"external_id,omitempty" gorm:"COLUMN:external_id"`
	Name       string    `json:"name,omitempty"`
	Segments   []Segment `json:"segments,omitempty"`
	Seq        uint64    `json:"seq,omitempty"`
}

type Segment struct {
	ID         uint64 `sql:"AUTO_INCREMENT" json:"id,omitempty"`
	ExternalID string `sql:"not null" json:"external_id,omitempty" gorm:"COLUMN:external_id"`
	TenantID   uint64 `gorm:"COLUMN:tenant_id" json:"tenant_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Seq        uint64 `json:"seq,omitempty"`
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
	db := tenantStore.DbStore.Db.Joins("JOIN tenants ON segments.tenant_id = tenants.id").
		Where("tenants.id = ? OR tenants.external_id = ?", tenantId, tenantId).
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

func (tenantStore *tenantStore) addTenant(tenant *Tenant) error {
	log.Println("In tenantStore addTenant().")

	var tenants []Tenant
	tx := tenantStore.DbStore.Db.Begin()

	tx = tx.Find(&tenants)
	err := common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	tenant.Seq = uint64(len(tenants))

	tx = tx.Create(tenant)
	err = common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

func (tenantStore *tenantStore) addSegment(tenantId uint64, segment *Segment) error {
	var err error
	tx := tenantStore.DbStore.Db.Begin()

	var segments []Segment
	tx = tx.Where("tenant_id = ?", tenantId).Find(&segments)
	err = common.GetDbErrors(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	segment.Seq = uint64(len(segments))
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

func (tenantStore *tenantStore) getTenant(id string) (Tenant, error) {
	ten := Tenant{}
	var count int
	log.Println("In getTenant()")
	db := tenantStore.DbStore.Db.Where("id = ?", id).First(&ten).Count(&count)
	err := common.GetDbErrors(db)
	if err != nil {
		return ten, err
	}
	if count == 0 {
		return ten, common.NewError404("tenant", id)
	}
	return ten, nil
}

func (tenantStore *tenantStore) getSegment(tenantId string, segmentId string) (Segment, error) {
	seg := Segment{}
	var count int
	db := tenantStore.DbStore.Db.Where("tenant_id = ? AND id = ?", tenantId, segmentId).
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

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (tenantStore *tenantStore) CreateSchemaPostProcess() error {
	db := tenantStore.Db
	log.Printf("tenantStore.CreateSchemaPostProcess(), DB is %v", db)
	db.Model(&Tenant{}).AddUniqueIndex("idx_name_extid", "name", "external_id")
	db.Model(&Segment{}).AddUniqueIndex("idx_tenant_name_extid", "tenant_id", "name", "external_id")
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}
