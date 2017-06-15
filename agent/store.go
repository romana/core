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
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
)

// agentStore is a backing storage. Agent will likely use
// sqlite which is not very reliable in concurrent access scenario,
// so we are going to guard access with mutex.
type agentStore struct {
	db *sql.DB
	mu *sync.RWMutex
}

// GetDb implements firewall.FirewallStore
func (agentStore agentStore) GetDB() *sql.DB {
	return agentStore.db
}

// GetMutex implements firewall.FirewallStore
func (agentStore agentStore) GetMutex() *sync.RWMutex {
	return agentStore.mu
}

// NewStore returns initialized agentStore.
func NewStore(agent *Agent) (*agentStore, error) {
	db, err := sql.Open("sqlite3", a.localDbFile)
	if err != nil {
		return nil, err
	}

	createTable := `CREATE TABLE IF NOT EXISTS routes (
		id integer primary key autoincrement,
		ip varchar,
		mask varchar
		kind varchar,
		spec varchar,
		status varchar
	)`
	_, err = db.Exec(createTable, args)

	datastore := agentStore{
		mu: &sync.RWMutex{},
		db: db,
	}
	return &datastore, nil
}

// Route is a model to store managed routes
type Route struct {
	ID     int
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

// deleteRoute deletes the route based on ID of the provided route.
func (agentStore *agentStore) deleteRoute(route *Route) error {
	log.Trace(trace.Inside, "Acquiring store mutex for deleteRoute")
	agentStore.mu.Lock()
	defer func() {
		log.Trace(trace.Inside, "Releasing store mutex for deleteRoute")
		agentStore.mu.Unlock()
	}()
	log.Trace(trace.Inside, "Acquired store mutex for deleteRoute")

	st, err := agentStore.db.Prepare("DELETE FROM routes WHERE id = ?")
	if err != nil {
		return err
	}
	res, err := st.Exec(route.ID)
	if err != nil {
		return err
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
	st, err := agentStore.db.Prepare("SELECT id,ip,mask,kind,spec,status FROM routes WHERE ip = ?")
	if err != nil {
		return nil, err
	}
	res, err := st.Query(routeIface)
	defer res.Close()

	if err != nil {
		return nil, err
	}

	if !res.Next() {
		return nil, common.NewError("Cannot find route for %s", routeIface)
	}
	route := &Route{}
	err = res.Scan(route)
	return route, err
}

func (agentStore *agentStore) addNetIf(netif *NetIf) error {
	stmt, err := agentStore.db.Prepare("INSERT INTO netif (ip,mac, name) VALUES (?,?,?)")
	if err != nil {
		return err
	}
	res, err := stmt.Exec(netif.IP, netif.Mac, netif.Name)
	if err != nil {
		return err
	}
	return nil
}

func (agentStore *agentStore) findNetIf(netif *NetIf) error {
	stmt, err := agentStore.db.Prepare("SELECT ip, mac, name FROM netif WHERE netif.ip = ?")
	if err != nil {
		return err
	}
	rows, err := stmt.Query(netif.IP.String())
	if err != nil {
		return err
	}
	if !rows.Next() {
		return common.NewError404("interface", fmt.Sprintf("mac: %s", netif.Mac))
	}
	return nil
}

func (agentStore *agentStore) listNetIfs() ([]NetIf, error) {
	stmt, err := agentStore.db.Prepare("SELECT ip, mac, name FROM netif")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	retval := make([]NetIf, 0)
	found := false
	for {
		if !rows.Next() {
			if !found {
				return nil, common.NewError404("interface", fmt.Sprintf("mac: %s", netif.Mac))
			}
			break

		}
	}
	return nil
}

func (agentStore *agentStore) deleteNetIf(netif *NetIf) error {
	stmt, err := agentStore.db.Prepare("DELETE FROM netifs WHERE ip = ?")
	if err != nil {
		return err
	}
	res, err := stmt.Exec(netif.IP)
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
	stmt, err := agentStore.db.Prepare("INSERT INTO routes (ip, mask, kind, spec, status) VALUES (?,?,?,?,?)")
	if err != nil {
		return err
	}
	res, err := stmt.Exec(route.IP, route.Mask, route.Spec, route.Status)
	if err != nil {
		return err
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
	stmt, err := agentStore.db.Prepare("SELECT ip, kind, mask,spec,status FROM routes")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	retval := make([]NetIf, 0)
	found := false
	for {
		if !rows.Next() {
			if !found {
				return nil, common.NewError404("interface", fmt.Sprintf("mac: %s", netif.Mac))
			}
			break
		}
		cols := rows.Columns()
		route := Route{IP: cols[0],
			Kind:   cols[1],
			Mask:   cols[2],
			Spec:   cols[3],
			Status: cols[4],
		}
		retval = append(retval, route)
	}
	return retval, nil
}
