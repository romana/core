// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package tenant

import (
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"github.com/romana/core/common"
	"log"
	"strconv"
)

type mysqlStore struct {
	info    common.MysqlStoreInfo
	connStr string
	db      *gorm.DB
}

func (mysqlStore *mysqlStore) setConfig(storeConfig map[string]interface{}) error {
	log.Println("In setConfig()")
	info := common.MysqlStoreInfo{}
	if storeConfig["host"] == nil {
		return errors.New("No host specified.")
	}
	info.Host = storeConfig["host"].(string)

	if storeConfig["port"] == nil {
		info.Port = 3306
	} else {
		port, err := strconv.ParseUint(storeConfig["port"].(string), 10, 64)
		if err != nil {
			return errors.New("Invalid port " + storeConfig["port"].(string))
		}
		if port == 0 {
			info.Port = 3306
		} else {
			info.Port = port
		}
	}
	if storeConfig["username"] == nil {
		return errors.New("No username specified.")
	}
	info.Username = storeConfig["username"].(string)

	if storeConfig["password"] == nil {
		return errors.New("No password specified.")
	}
	info.Password = storeConfig["password"].(string)

	if storeConfig["database"] == nil {
		return errors.New("No database specified.")
	}
	info.Database = storeConfig["database"].(string)

	mysqlStore.info = info
	mysqlStore.setConnString()

	return nil
}

func (mysqlStore *mysqlStore) validateConnectionInformation() error {
	return mysqlStore.connect()
}

func (mysqlStore *mysqlStore) setConnString() {
	info := mysqlStore.info
	mysqlStore.connStr = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", info.Username, info.Password, info.Host, info.Port, info.Database)
}

func (mysqlStore *mysqlStore) connect() error {
	log.Println("in connect(", mysqlStore.connStr, ")")
	if mysqlStore.connStr == "" {
		return errors.New("No connection information.")
	}
	db, err := gorm.Open("mysql", mysqlStore.connStr)
	if err != nil {
		return err
	}
	mysqlStore.db = &db
	return nil
}

func (mysqlStore *mysqlStore) listTenants() ([]Tenant, error) {
	var tenants []Tenant
	log.Println("In listTenants()", &tenants)
	mysqlStore.db.Find(&tenants)
	err := common.MakeMultiError(mysqlStore.db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println(tenants)
	return tenants, nil
}

func (mysqlStore *mysqlStore) listSegments(tenantId uint64) ([]Segment, error) {
	var segments []Segment
	log.Println("In listTenants()", &segments)
	mysqlStore.db.Where("tenant_id = ?", tenantId).Find(&segments)
	err := common.MakeMultiError(mysqlStore.db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println(segments)
	return segments, nil
}

func (mysqlStore *mysqlStore) addTenant(tenant *Tenant) error {
	var tenants []Tenant
	mysqlStore.db.Find(&tenants)

	//	myId := tenant.Id
	tenant.Seq = uint64(len(tenants) + 1)
	mysqlStore.db.Create(tenant)
	mysqlStore.db.NewRecord(*tenant)

	// TODO better way of getting sequence
	//
	//	var tenantSeq uint64
	//	for i := range tenants {
	//		if tenants[i].Id == myId {
	//			tenantSeq = uint64(i)
	//			tenant.Seq = tenantSeq
	//			mysqlStore.db.Save(tenant)
	//			log.Printf("Sequence for tenant %s is %d\n", tenants[i].Name, tenantSeq)
	//			break
	//		}
	//	}

	err := common.MakeMultiError(mysqlStore.db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}

func (mysqlStore *mysqlStore) findTenant(id uint64) (Tenant, error) {
	var tenants []Tenant
	log.Println("In findTenant()")
	mysqlStore.db.Find(&tenants)
	err := common.MakeMultiError(mysqlStore.db.GetErrors())
	if err != nil {
		return Tenant{}, err
	}
	for i := range tenants {
		if tenants[i].Id == id {
			tenants[i].Seq = uint64(i)
			return tenants[i], nil
		}
	}
	return Tenant{}, errors.New("Not found")
	//	tenant := Tenant{}
	//	mysqlStore.db.Where("id = ?", id).First(&tenant)
	//	err := common.MakeMultiError(mysqlStore.db.GetErrors())
	//	if err != nil {
	//		return tenant, err
	//	}
	//	return tenant, nil
}

func (mysqlStore *mysqlStore) addSegment(tenantId uint64, segment *Segment) error {
	var err error

	// TODO better way of getting sequence
	var segments []Segment
	mysqlStore.db.Where("tenant_id = ?", tenantId).Find(&segments)
	segment.Seq = uint64(len(segments) + 1)
	mysqlStore.db.NewRecord(*segment)
	segment.TenantId = tenantId
	mysqlStore.db.Create(segment)
//	myId := segment.Id

	//	var segmentSeq uint64
	//
	//	for i := range segments {
	//		if segments[i].Id == myId {
	//			segmentSeq = uint64(i)
	//			segments[i].Seq = segmentSeq
	//			log.Printf("Sequence for segment %s is %d\n", segments[i].Name, segmentSeq)
	//			mysqlStore.db.Save(segment)
	//			break
	//		}
	//	}

	err = common.MakeMultiError(mysqlStore.db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}

func (mysqlStore *mysqlStore) findSegment(tenantId uint64, id uint64) (Segment, error) {
	var segments []Segment
	log.Println("In listSegments()")
	mysqlStore.db.Where("tenant_id = ?", tenantId).Find(&segments)
	err := common.MakeMultiError(mysqlStore.db.GetErrors())
	if err != nil {
		return Segment{}, err
	}
	for i := range segments {
		if segments[i].Id == id {
			segments[i].Seq = uint64(i)
			return segments[i], nil
		}
	}
	return Segment{}, errors.New("Not found")
	//	segment := Segment{}
	//	mysqlStore.db.Where("tenant_id = ? AND id = ?", tenantId, id).First(&segment)
	//	err := common.MakeMultiError(mysqlStore.db.GetErrors())
	//	if err != nil {
	//		return segment, err
	//	}
	//	return segment, nil
}

//func (mysqlStore *mysqlStore) listSegments() ([]Tenant, error) {
//	var tenants []Segment
//	log.Println("In listSegments()")
//	mysqlStore.db.Find(&tenant)
//	err := common.MakeMultiError(mysqlStore.db.GetErrors())
//	if err != nil {
//		return nil, err
//	}
//	log.Println(tenants)
//	return tenants, nil
//}

func (mysqlStore *mysqlStore) createSchema(force bool) error {
	log.Println("tenant: in createSchema(", force, ")")
	// Connect to mysql database
	schemaName := mysqlStore.info.Database
	mysqlStore.info.Database = "mysql"
	mysqlStore.setConnString()
	err := mysqlStore.connect()

	if err != nil {
		return err
	}
	var sql string
	if force {
		sql = fmt.Sprintf("DROP DATABASE IF EXISTS %s", schemaName)
		res, err := mysqlStore.db.DB().Exec(sql)
		if err != nil {
			return err
		}

		rows, _ := res.RowsAffected()
		log.Println(sql, ": ", rows)
	}

	sql = fmt.Sprintf("CREATE DATABASE %s", schemaName)
	res, err := mysqlStore.db.DB().Exec(sql)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	log.Println(sql, ": ", rows)
	mysqlStore.info.Database = schemaName
	mysqlStore.setConnString()
	err = mysqlStore.connect()
	if err != nil {
		return err
	}
	log.Println("Creating segments table")
	mysqlStore.db.CreateTable(&Segment{})

	// Sequence numbers are unique for segments within a tenant.
	mysqlStore.db.Model(&Segment{}).AddUniqueIndex("idx_tenant_id_seq", "tenant_id", "seq")
	// Segment ID is unique within a tenant.
	mysqlStore.db.Model(&Segment{}).AddUniqueIndex("idx_segment_tenant_name", "tenant_id", "name")

	log.Println("Creating tenants table")
	mysqlStore.db.CreateTable(&Tenant{})
	// Tenant name is unique.
	mysqlStore.db.Model(&Tenant{}).AddUniqueIndex("idx_name", "name")
	// Sequence name is unique for tenants in a datacenter (for now, all).
	mysqlStore.db.Model(&Tenant{}).AddUniqueIndex("idx_seq", "seq")

	errs := mysqlStore.db.GetErrors()
	log.Println("Errors", errs)
	err2 := common.MakeMultiError(errs)

	if err2 != nil {
		return err2
	}
	return nil

}
