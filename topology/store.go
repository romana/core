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

// Package topology host, TOR definitions.
package topology

import (
	"log"

	_ "github.com/go-sql-driver/mysql"

	"github.com/romana/core/common"

	"strconv"
)

type Host struct {
	Id        uint64 `sql:"AUTO_INCREMENT" json:"id"`
	Name      string `json:"name"`
	Ip        string `json:"ip" sql:"unique"`
	RomanaIp  string `json:"romana_ip" sql:"unique"`
	AgentPort uint64 `json:"agent_port"`
	//	tor         *Tor
}

type Tor struct {
	Id         uint64 `sql:"AUTO_INCREMENT"`
	datacenter *common.Datacenter
}

// Backing store
type topoStore struct {
	common.DbStore
}

func (topoStore topoStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = Host{}
	retval[1] = common.Datacenter{}
	return retval
}

func (topoStore topoStore) CreateSchemaPostProcess() error {
	return nil
}

func (topoStore *topoStore) findHost(id uint64) (Host, error) {
	host := Host{}
	topoStore.DbStore.Db.Where("id = ?", id).First(&host)
	err := common.MakeMultiError(topoStore.DbStore.Db.GetErrors())
	if err != nil {
		return host, err
	}
	return host, nil
}

func (topoStore *topoStore) listHosts() ([]Host, error) {
	var hosts []Host
	log.Println("In listHosts()")
	topoStore.DbStore.Db.Find(&hosts)
	err := common.MakeMultiError(topoStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println("MySQL found hosts:", hosts)
	return hosts, nil
}

func (topoStore *topoStore) addHost(host *Host) (string, error) {
	topoStore.DbStore.Db.NewRecord(*host)
	topoStore.DbStore.Db.Create(host)
	err := common.MakeMultiError(topoStore.DbStore.Db.GetErrors())
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(host.Id, 10), nil
}
