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

// store.go contains functionality for agent's backend store.
package agent

import (
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/core/common/store"
	"github.com/romana/core/pkg/util/firewall"
	log "github.com/romana/rlog"
	"sync"
)

// agentStore is a backing storage. Agent will likely use
// sqlite which is not very reliable in concurrent access scenario,
// so we are going to guard access with mutex.
type agentStore struct {
	*store.RdbmsStore
	mu *sync.RWMutex
}

// GetDb implements firewall.FirewallStore
func (agentStore agentStore) GetDb() store.RdbmsStore {
	return *agentStore.RdbmsStore
}

// GetMutex implements firewall.FirewallStore
func (agentStore agentStore) GetMutex() *sync.RWMutex {
	return agentStore.mu
}

// Entities implements Entities method of
// Service interface.
func (agentStore *agentStore) Entities() []interface{} {
	retval := make([]interface{}, 3)
	retval[0] = new(Route)
	retval[1] = new(firewall.IPtablesRule)
	retval[2] = new(NetIf)
	return retval
}

// NewStore returns initialized agentStore.
func NewStore(config common.ServiceConfig) (*agentStore, error) {
	storeConfigMap := config.ServiceSpecific["store"].(map[string]interface{})
	store := agentStore{
		mu: &sync.RWMutex{},
	}
	store.ServiceStore = &store
	storeConfig, err := common.MakeStoreConfig(storeConfigMap)
	if err != nil {
		return nil, err
	}
	store.SetConfig(storeConfig)

	return &store, nil
}

// Route is a model to store managed routes
type Route struct {
	ID     uint64 `sql:"AUTO_INCREMENT"`
	IP     string
	Mask   string
	Kind   targetKind
	Spec   string
	Status string
}

// targetKind is a an IP route destination type.
type targetKind string

const (
	device  targetKind = "dev"
	gateway targetKind = "gw"
)

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (agentStore *agentStore) CreateSchemaPostProcess() error {
	return nil
}

func (agentStore *agentStore) deleteRoute(route *Route) error {
	log.Trace(trace.Inside, "Acquiring store mutex for deleteRoute")
	agentStore.mu.Lock()
	defer func() {
		log.Trace(trace.Inside, "Releasing store mutex for deleteRoute")
		agentStore.mu.Unlock()
	}()
	log.Trace(trace.Inside, "Acquired store mutex for deleteRoute")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Delete(route)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}

	return nil
}

func (agentStore *agentStore) findRouteByIface(routeIface string) (*Route, error) {
	log.Trace(trace.Inside, "Acquiring store mutex for findRoute")
	agentStore.mu.Lock()
	defer func() {
		log.Trace(trace.Inside, "Releasing store mutex for findRoute")
		agentStore.mu.Unlock()
	}()
	log.Trace(trace.Inside, "Acquired store mutex for findRoute")

	var route Route
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Where("ip = ?", routeIface).First(&route)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &route, nil
}

func (agentStore *agentStore) addNetIf(netif *NetIf) error {
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Create(netif)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

func (agentStore *agentStore) findNetIf(netif *NetIf) error {
	db := agentStore.DbStore.Db
	var count int
	agentStore.DbStore.Db.Where(netif).First(netif).Count(&count)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	if count == 0 {
		return common.NewError404("interface", fmt.Sprintf("mac: %s", netif.Mac))
	}
	return nil
}

func (agentStore *agentStore) listNetIfs() ([]NetIf, error) {
	db := agentStore.DbStore.Db
	var netifs []NetIf
	agentStore.DbStore.Db.Find(&netifs)
	err := common.GetDbErrors(db)
	if err != nil {
		return nil, err
	}
	return netifs, nil
}

func (agentStore *agentStore) deleteNetIf(netif *NetIf) error {
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Delete(netif)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

func (agentStore *agentStore) addRoute(route *Route) error {
	log.Info("Acquiring store mutex for addRoute")
	agentStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for addRoute")
		agentStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for addRoute")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Create(route)
	if db.Error != nil {
		return db.Error
	}
	agentStore.DbStore.Db.NewRecord(*route)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}
	return nil
}

func (agentStore *agentStore) listRoutes() ([]Route, error) {
	log.Trace(trace.Inside, "Acquiring store mutex for listRoutes")
	agentStore.mu.Lock()
	defer func() {
		log.Trace(trace.Inside, "Releasing store mutex for listRoutes")
		agentStore.mu.Unlock()
	}()
	log.Trace(trace.Inside, "Acquired store mutex for listRoutes")

	var routes []Route
	agentStore.DbStore.Db.Find(&routes)
	err := common.MakeMultiError(agentStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return routes, nil
}
