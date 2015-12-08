// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

import (
//	"database/sql"
//	"github.com/romana/core/common"
)

type Vm struct {
	//	Id        uint64 `json:"id"`
	Ip        string `json:"ip"`
	TenantId  uint64 `json:"tenant_id"`
	SegmentId uint64 `json:"segment_id"`
	HostId    string `json:"host_id"`
	Name      string `json:"instance"`
	Seq       uint64 `json:"sequence"`
}

type IpamHost struct {
	Vms []IpamVm
	Id  string `sql:"unique_index"`
}

type IpamVm struct {
	Vm
	Id uint64 `sql:"AUTO_INCREMENT"`
	//	IpamHostId sql.NullString
}
