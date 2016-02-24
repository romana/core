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
	"errors"
	_ "github.com/go-sql-driver/mysql"

	"github.com/romana/core/common"
	"log"
)

// Backing store
type tenantStore struct {
	common.DbStore
}

<<<<<<< HEAD
func (tenantStore tenantStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = Tenant{}
	retval[1] = Segment{}
	return retval
=======
	addTenant(tenant *Tenant) error
	findTenant(id uint64) (Tenant, error)
	addSegment(tenantId uint64, segment *Segment) error
	findSegment(tenantId uint64, id uint64) (Segment, error)

	listTenants() ([]Tenant, error)
	listSegments(tenantId uint64) ([]Segment, error)
>>>>>>> master
}

type Tenant struct {
	Id       uint64 `sql:"AUTO_INCREMENT"`
	Name     string
	Segments []Segment
	Seq      uint64
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
	log.Println("In listTenants()", &segments)
	tenantStore.DbStore.Db.Where("tenant_id = ?", tenantId).Find(&segments)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println(segments)
	return segments, nil
}

func (tenantStore *tenantStore) addTenant(tenant *Tenant) error {
	var tenants []Tenant
	tenantStore.DbStore.Db.Find(&tenants)

	//	myId := tenant.Id
	tenant.Seq = uint64(len(tenants) + 1)
	tenantStore.DbStore.Db.Create(tenant)
	tenantStore.DbStore.Db.NewRecord(*tenant)

	// TODO better way of getting sequence
	//
	//	var tenantSeq uint64
	//	for i := range tenants {
	//		if tenants[i].Id == myId {
	//			tenantSeq = uint64(i)
	//			tenant.Seq = tenantSeq
	//			tenantStore.DB().Save(tenant)
	//			log.Printf("Sequence for tenant %s is %d\n", tenants[i].Name, tenantSeq)
	//			break
	//		}
	//	}

	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}

func (tenantStore *tenantStore) findTenant(id uint64) (Tenant, error) {
	var tenants []Tenant
	log.Println("In findTenant()")
	tenantStore.DbStore.Db.Find(&tenants)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return Tenant{}, err
	}
	for i := range tenants {
		if tenants[i].Id == id {
			return tenants[i], nil
		}
	}
	return Tenant{}, errors.New("Not found")
	//	tenant := Tenant{}
	//	tenantStore.DB().Where("id = ?", id).First(&tenant)
	//	err := common.MakeMultiError(tenantStore.DB().GetErrors())
	//	if err != nil {
	//		return tenant, err
	//	}
	//	return tenant, nil
}

func (tenantStore *tenantStore) addSegment(tenantId uint64, segment *Segment) error {
	var err error

	// TODO better way of getting sequence
	var segments []Segment
	tenantStore.DbStore.Db.Where("tenant_id = ?", tenantId).Find(&segments)
	segment.Seq = uint64(len(segments) + 1)
	tenantStore.DbStore.Db.NewRecord(*segment)
	segment.TenantId = tenantId
	tenantStore.DbStore.Db.Create(segment)
	//	myId := segment.Id

	//	var segmentSeq uint64
	//
	//	for i := range segments {
	//		if segments[i].Id == myId {
	//			segmentSeq = uint64(i)
	//			segments[i].Seq = segmentSeq
	//			log.Printf("Sequence for segment %s is %d\n", segments[i].Name, segmentSeq)
	//			tenantStore.DB().Save(segment)
	//			break
	//		}
	//	}

	err = common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}

func (tenantStore tenantStore) CreateSchemaPostProcess() error {
	return nil
}

func (tenantStore *tenantStore) findSegment(tenantId uint64, id uint64) (Segment, error) {
	var segments []Segment
	log.Println("In listSegments()")
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
	//	segment := Segment{}
	//	tenantStore.DB().Where("tenant_id = ? AND id = ?", tenantId, id).First(&segment)
	//	err := common.MakeMultiError(tenantStore.DB().GetErrors())
	//	if err != nil {
	//		return segment, err
	//	}
	//	return segment, nil
}

//func (mysqlStore *mysqlStore) listSegments() ([]Tenant, error) {
//	var tenants []Segment
//	log.Println("In listSegments()")
//	tenantStore.DB().Find(&tenant)
//	err := common.MakeMultiError(tenantStore.DB().GetErrors())
//	if err != nil {
//		return nil, err
//	}
//	log.Println(tenants)
//	return tenants, nil
//}
