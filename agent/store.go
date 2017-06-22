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
func (agentStore agentStore) GetDb() *sql.DB {
	return agentStore.db
}

// GetMutex implements firewall.FirewallStore
func (agentStore agentStore) GetMutex() *sync.RWMutex {
	return agentStore.mu
}

// NewStore returns initialized agentStore.
func NewStore(agent *Agent) (agentStore, error) {
	db, err := sql.Open("sqlite3", agent.localDBFile)

	datastore := agentStore{
		mu: &sync.RWMutex{},
		db: db,
	}

	if err != nil {
		return datastore, err
	}
	var createTable string

	createTable = `CREATE TABLE IF NOT EXISTS routes (
		id integer primary key autoincrement,
		ip varchar,
		mask varchar
		kind varchar,
		spec varchar,
		status varchar
	)`
	_, err = db.Exec(createTable)
	if err != nil {
		return datastore, err
	}

	createTable = `CREATE TABLE IF NOT EXISTS iptables_rules (
		body TEXT PRIMARY KEY,
		state VARCHAR
	)`
	_, err = db.Exec(createTable)
	if err != nil {
		return datastore, err
	}

	createTable = `CREATE TABLE IF NOT EXISTS netifs (
		name varchar,
		mac varchar primary key,
		ip varchar
	)`
	_, err = db.Exec(createTable)
	if err != nil {
		return datastore, err
	}

	return datastore, nil
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
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return err
	}
	_, err = st.Exec(route.ID)
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

	st, err := agentStore.db.Prepare("SELECT id,ip,mask,kind,spec,status FROM routes WHERE ip = ?")
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return nil, err
	}
	res, err := st.Query(routeIface)
	if res != nil {
		defer res.Close()
	}
	if err != nil {
		return nil, err
	}

	if !res.Next() {
		return nil, common.NewError("Cannot find route for %s", routeIface)
	}
	route := &Route{}
	err = res.Scan(&route.ID, &route.IP, &route.Mask, &route.Spec, &route.Status)
	return route, err
}

func (agentStore *agentStore) addNetIf(netif *NetIf) error {
	st, err := agentStore.db.Prepare("INSERT INTO netifs (ip,mac, name) VALUES (?,?,?)")
	if err != nil {
		return err
	}
	if st != nil {
		defer st.Close()
	}
	_, err = st.Exec(netif.IP, netif.Mac, netif.Name)

	if err != nil {
		return err
	}
	return nil
}

func (agentStore *agentStore) findNetIf(netif *NetIf) error {
	st, err := agentStore.db.Prepare("SELECT ip, mac, name FROM netifs WHERE netif.ip = ?")
	if err != nil {
		return err
	}
	if st != nil {
		defer st.Close()
	}
	rows, err := st.Query(netif.IP.String())
	if rows != nil {
		defer rows.Close()
	}
	if err != nil {
		return err
	}
	if !rows.Next() {
		return common.NewError404("interface", fmt.Sprintf("mac: %s", netif.Mac))
	}
	rows.Scan(netif.IP, &netif.Mac, &netif.Name)
	return nil
}

func (agentStore *agentStore) listNetIfs() ([]NetIf, error) {
	st, err := agentStore.db.Prepare("SELECT ip, mac, name FROM netifs")
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return nil, err
	}
	rows, err := st.Query()
	if rows != nil {
		defer rows.Close()
	}
	if err != nil {
		return nil, err
	}
	netifs := make([]NetIf, 0)
	for rows.Next() {
		netif := NetIf{}
		err = rows.Scan(&netif.IP, &netif.Mac, &netif.Name)
		if err != nil {
			return netifs, err
		}
		netifs = append(netifs, netif)
	}
	return netifs, nil
}

func (agentStore *agentStore) deleteNetIf(netif *NetIf) error {
	st, err := agentStore.db.Prepare("DELETE FROM netifs WHERE ip = ?")
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return err
	}
	_, err = st.Exec(netif.IP)
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
	st, err := agentStore.db.Prepare("INSERT INTO routes (ip, mask, kind, spec, status) VALUES (?,?,?,?,?)")

	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return err
	}
	_, err = st.Exec(route.IP, route.Mask, route.Spec, route.Status)
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
	st, err := agentStore.db.Prepare("SELECT ip, kind, mask,spec,status FROM routes")
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return nil, err
	}
	rows, err := st.Query()
	if rows != nil {
		defer rows.Close()
	}
	if err != nil {
		return nil, err
	}
	routes := make([]Route, 0)
	for rows.Next() {
		route := Route{}
		err = rows.Scan(&route.IP, &route.Kind, &route.Mask, &route.Spec, &route.Status)
		if err != nil {
			return routes, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}
