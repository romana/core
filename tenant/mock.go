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
	"log"
)

type mockStore struct {
	tenants    map[uint64]Tenant
	id         uint64
	segments   map[uint64]map[uint64]Segment
	segmentsId map[uint64]uint64
}

func (mockStore *mockStore) setConfig(storeConfig map[string]interface{}) error {
	return nil
}

func (mockStore *mockStore) validateConnectionInformation() error {
	return nil
}

func (mockStore *mockStore) setConnString() {

}

func (mockStore *mockStore) connect() error {
	mockStore.tenants = make(map[uint64]Tenant)
	mockStore.segments = make(map[uint64]map[uint64]Segment)
	mockStore.segmentsId = make(map[uint64]uint64)
	mockStore.id = 1
	return nil
}

func (mockStore *mockStore) listTenants() ([]Tenant, error) {
	tenants := make([]Tenant, len(mockStore.tenants))
	for k, v := range mockStore.tenants {
		tenants[k-1] = v
	}
	return tenants, nil
}

func (mockStore *mockStore) listSegments(tenantId uint64) ([]Segment, error) {
	segments := make([]Segment, len(mockStore.segments[tenantId]))
	for k, v := range mockStore.segments[tenantId] {
		segments[k-1] = v
	}
	return segments, nil
}

func (mockStore *mockStore) addTenant(tenant *Tenant) error {
	tenant.Id = mockStore.id
	tenant.Seq = mockStore.id-1
	mockStore.tenants[mockStore.id] = *tenant
	mockStore.id++
	return nil
}

func (mockStore *mockStore) findTenant(id uint64) (Tenant, error) {
	return mockStore.tenants[id], nil

}

func (mockStore *mockStore) addSegment(tenantId uint64, segment *Segment) error {
	log.Printf("Mock: Adding segment %s for tenant %d\n", segment.Name, tenantId)
	if mockStore.segments[tenantId] == nil {
		mockStore.segments[tenantId] = make(map[uint64]Segment)
		mockStore.segmentsId[tenantId] = 1
	}

	segment.Id = uint64(mockStore.segmentsId[tenantId])
	segment.Seq = uint64(mockStore.segmentsId[tenantId])-1
	mockStore.segments[tenantId][mockStore.segmentsId[tenantId]] = *segment
	mockStore.segmentsId[tenantId]++
	log.Println("Mock: Segments now", mockStore.segments)
	return nil
}

func (mockStore *mockStore) findSegment(tenantId uint64, id uint64) (Segment, error) {
	return mockStore.segments[tenantId][id], nil
}

func (mockStore *mockStore) createSchema(force bool) error {
	return nil
}
