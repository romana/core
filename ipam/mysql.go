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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

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

func (mysqlStore *mysqlStore) addVm(stride uint, vm *Vm) error {
	tx := mysqlStore.db.Begin()

	row := tx.Model(IpamVm{}).Where("host_id = ? AND segment_id = ?", vm.HostId, vm.SegmentId).Select("IFNULL(MAX(seq),-1)+1").Row()
	row.Scan(&vm.Seq)
	log.Printf("New sequence is %d\n", vm.Seq)

	// vmSeq is the sequence number of VM in a given host
	effectiveVmSeq := getEffectiveSeq(vm.Seq, stride)
	log.Printf("Effective sequence for seq %d (stride %d): %d\n", vm.Seq, stride, effectiveVmSeq)
	vm.EffectiveSeq = effectiveVmSeq
	ipamVm := IpamVm{Vm: *vm}
	tx.NewRecord(ipamVm)
	tx.Create(&ipamVm)
	log.Printf("YOYO TX: [%v] mysqlstore.db [%v] errors [%v]\n", tx, mysqlStore.db, tx.GetErrors())
	err := common.MakeMultiError(tx.GetErrors())
	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()

	return nil
}

func getEffectiveSeq(vmSeq uint64, stride uint) uint64 {
	var effectiveVmSeq uint64
	effectiveVmSeq = 3 + (1<<stride)*vmSeq
	return effectiveVmSeq
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

func (mysqlStore *mysqlStore) createSchema(force bool) error {
	log.Println("in createSchema(", force, ")")
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
	log.Println("Creating vms table.")
	ipamVm := IpamVm{}
	mysqlStore.db.CreateTable(&ipamVm)
	// Sequence numbers are unique for VMs per host / tenant combination
	mysqlStore.db.Model(&IpamVm{}).AddUniqueIndex("idx_segment_host_seq", "segment_id", "host_id", "seq")

	//	log.Println("Creating hosts table.")
	//	mysqlStore.db.CreateTable(&IpamHost{})
	//
	//	log.Println("Creating segments table.")
	//	mysqlStore.db.CreateTable(&IpamHost{})

	errs := mysqlStore.db.GetErrors()
	log.Println("Errors", errs)
	err2 := common.MakeMultiError(errs)

	if err2 != nil {
		return err2
	}
	return nil

}
