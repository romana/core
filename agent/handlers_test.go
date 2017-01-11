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

// handlers_test.go contains tests cases for handlers
package agent

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/romana/core/common"
	"os"
	"testing"
)

const (
	dbName = "/var/tmp/agentTest.sqlite3"
)

var (
	err error
)

func _makeAgent(t *testing.T) *Agent {
	t.Logf("Trying to delete %s", dbName)
	os.Remove(dbName)
	_, err = sql.Open("sqlite3", dbName)
	if err != nil {
		t.Fatal(err)
	}
	storeConfig := common.InitMap(common.KV("type", "sqlite3"), common.KV("database", dbName))
	serviceConfig := common.InitMap(common.KV("store", storeConfig))
	config := common.ServiceConfig{ServiceSpecific: serviceConfig}
	store, err := NewStore(config)
	if err != nil {
		t.Errorf("Error creating schema: %v", err)
	}
	err = store.CreateSchema(false)
	if err != nil {
		t.Errorf("Error creating schema: %v", err)
	}
	err = store.Connect()
	if err != nil {
		t.Errorf("Error connecting to store: %v", err)
	}
	agent := Agent{store: *store}
	t.Logf("Store value: %+v", store)
	return &agent
}

func TestVmDownHandler(t *testing.T) {
	agent := _makeAgent(t)
	if t.Failed() {
		t.FailNow()
	}
	// Test interface that is not found for now -- DB is empty, so
	// nothing will be found.
	netif := NetIf{Mac: "aa:bb:cc:dd:ee:ff"}
	resp, err := agent.vmDownHandler(&netif, common.RestContext{})
	if err == nil {
		t.Errorf("Expected error on vmDwonHandler, received response %+v", resp)
	} else {
		t.Logf("Got error as expected: %v", err)
	}
}
