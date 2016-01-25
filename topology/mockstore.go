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
package topology

import (
	"log"

	"strconv"
)

type mockStore struct {
	hosts map[uint64]*Host
	id    uint64
}

func (mockStore *mockStore) setConfig(storeConfig map[string]interface{}) error {
	return nil
}

func (mockStore *mockStore) validateConnectionInformation() error {
	return nil
}

func (mockStore *mockStore) findHost(id uint64) (Host, error) {
	return *mockStore.hosts[id], nil
}

func (mockStore *mockStore) listHosts() ([]Host, error) {
	retval := make([]Host, len(mockStore.hosts))
	for k, v := range mockStore.hosts {
		log.Println(k, ": ", v)
		retval[k-1] =*v
	}
	log.Println("Listing hosts", retval)
	return retval, nil
}

func (mockStore *mockStore) addHost(host *Host) (string, error) {
	log.Println("ID: ", mockStore.id)
	mockStore.hosts[mockStore.id] = host
	host.Id = mockStore.id
	log.Printf("Mock: Adding host name %s, Romana IP %s under ID %d\n", host.Name, host.RomanaIp, mockStore.id)
	log.Println(mockStore.hosts)
	mockStore.id++
	return strconv.FormatUint(host.Id, 10), nil
}

func (mockStore *mockStore) connect() error {
	log.Println("Connecting to mock store")
	mockStore.hosts = make(map[uint64]*Host)
	mockStore.id = 1
	return nil
}

func (mockStore *mockStore) createSchema(force bool) error {
	return nil
}
