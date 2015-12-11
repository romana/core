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
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

import (
	"log"
)

type mockStore struct {
	hostToSegmentToVm map[string]map[string]map[uint64]IpamVm
	vmId              map[string]map[string]uint64
}

func (mockStore *mockStore) addVm(stride uint, vm *Vm) error {
	segmentToVm := mockStore.hostToSegmentToVm[vm.HostId]
	if segmentToVm == nil {
		segmentToVm = make(map[string]map[uint64]IpamVm)
		mockStore.hostToSegmentToVm[vm.HostId] = segmentToVm
		mockStore.vmId[vm.HostId] = make(map[string]uint64)
	}
	vms := segmentToVm[vm.SegmentId]

	if vms == nil {
		vms = make(map[uint64]IpamVm)
		segmentToVm[vm.SegmentId] = vms
		mockStore.vmId[vm.HostId][vm.SegmentId] = 1
	}
	vm.Seq = mockStore.vmId[vm.HostId][vm.SegmentId]-1
	mockStore.vmId[vm.HostId][vm.SegmentId]++
	log.Printf("New sequence is %d\n", vm.Seq)

	effectiveVmSeq := getEffectiveSeq(vm.Seq, stride)
	log.Printf("Effective sequence for seq %d (stride %d): %d\n", vm.Seq, stride, effectiveVmSeq)
	vm.EffectiveSeq = effectiveVmSeq
	return nil
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
	mockStore.hostToSegmentToVm = make(map[string]map[string]map[uint64]IpamVm)
	mockStore.vmId = make(map[string]map[string]uint64)
	return nil
}

func (mockStore *mockStore) createSchema(force bool) error {
	return nil
}
