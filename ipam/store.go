// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/romana/core/common"
	"log"
	"strings"
)

type Endpoint struct {
	Ip           string         `json:"ip"`
	TenantId     string         `json:"tenant_id"`
	SegmentId    string         `json:"segment_id"`
	HostId       string         `json:"host_id"`
	Name         string         `json:"instance"`
	RequestToken sql.NullString `json:"request_token" sql:"unique"`
	// Ordinal number of this Endpoint in the host/tenant combination
	Seq uint64 `json:"sequence",json:"-"`
	// Calculated effective sequence number of this Endpoint --
	// taking into account stride (endpoint space bits)
	// and alignment thereof. This is used in IP calculation.
	EffectiveSeq uint64 `json:"effective_sequence",json:"-"`
	// Whether it is in use (for purposes of reclaiming)
	InUse bool   `json:"in_use",json:"-"`
	Id    uint64 `sql:"AUTO_INCREMENT"`
}

type IpamHost struct {
	Endpoints []Endpoint
	Id        string `sql:"unique_index"`
}

type IpamSegment struct {
	Endpoints []Endpoint
	Id        string `sql:"unique_index"`
}

type ipamStore struct {
	common.DbStore
}

func (ipamStore *ipamStore) deleteEndpoint(ip string) (Endpoint, error) {
	tx := ipamStore.DbStore.Db.Begin()
	results := make([]Endpoint, 0)
	tx.Where(&Endpoint{Ip: ip}).Find(&results)
	if len(results) == 0 {
		tx.Rollback()
		return Endpoint{}, common.NewError404("Endpoint", ip)
	}
	if len(results) > 1 {
		// This cannot happen by constraints...
		tx.Rollback()
		errMsg := fmt.Sprintf("Expected one result for ip %s, got %v", ip, results)
		log.Printf(errMsg)
		return Endpoint{}, common.NewError500(errors.New(errMsg))
	}

	tx = tx.Model(Endpoint{}).Where("ip = ?", ip).Update("in_use", false)
	err := common.MakeMultiError(tx.GetErrors())
	if err != nil {
		tx.Rollback()
		return Endpoint{}, err
	}
	tx.Commit()
	return results[0], nil
}

func (ipamStore *ipamStore) addEndpoint(endpoint *Endpoint, upToEndpointIpInt uint64, stride uint) error {
	var err error
	tx := ipamStore.DbStore.Db.Begin()
	hostId := endpoint.HostId
	endpoint.InUse = true
	segId := endpoint.SegmentId

	where := "host_id = ? AND segment_id = ? AND in_use = 0"
	sel := "min(seq)"
	log.Printf("Calling SELECT %s FROM endpoints WHERE %s;", sel, fmt.Sprintf(strings.Replace(where, "?", "%s", 2), hostId, segId))
	row := tx.Model(Endpoint{}).Where(where, hostId, segId).Select(sel).Row()
	seq := sql.NullInt64{}
	row.Scan(&seq)
	log.Printf("minseq: %v", seq)
	if !seq.Valid {
		// TODO can this be done in a single query?
		where = "host_id = ? AND segment_id = ? AND in_use = 1"
		sel = "ifnull(max(seq),-1)+1"
		log.Printf("Calling SELECT %s FROM endpoints WHERE %s;", sel, fmt.Sprintf(strings.Replace(where, "?", "%s", 2), hostId, segId))
		row := tx.Model(Endpoint{}).Where(where, hostId, segId).Select(sel).Row()
		seq = sql.NullInt64{}
		row.Scan(&seq)
		log.Printf("maxseq: %v", seq)
	}
	endpoint.Seq = uint64(seq.Int64)

	log.Printf("New sequence is %d\n", endpoint.Seq)

	// EndpointSeq is the sequence number of Endpoint in a given host
	endpoint.EffectiveSeq = getEffectiveSeq(endpoint.Seq, stride)
	log.Printf("Effective sequence for seq %d (stride %d): %d\n", endpoint.Seq, stride, endpoint.EffectiveSeq)

	ipInt := upToEndpointIpInt | endpoint.EffectiveSeq
	endpoint.Ip = common.IntToIPv4(ipInt).String()
	tx.NewRecord(Endpoint{})
	tx = tx.Create(endpoint)
	err = common.MakeMultiError(tx.GetErrors())
	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

// getEffectiveSeq gets effective sequence number of a Endpoint
// on a given host.
func getEffectiveSeq(EndpointSeq uint64, stride uint) uint64 {
	var effectiveEndpointSeq uint64
	// We start with 3 because we reserve 1 for gateway
	// and 2 for DHCP.
	effectiveEndpointSeq = 3 + (1<<stride)*EndpointSeq
	return effectiveEndpointSeq
}

// Entities implements Entities method of Service interface.
func (ipamStore *ipamStore) Entities() []interface{} {
	retval := make([]interface{}, 1)
	retval[0] = &Endpoint{}
	return retval
}

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (ipamStore *ipamStore) CreateSchemaPostProcess() error {
	db := ipamStore.Db
	log.Printf("ipamStore.CreateSchemaPostProcess(), DB is %v", db)
	db.Model(&Endpoint{}).AddUniqueIndex("idx_segment_host_seq", "segment_id", "host_id", "seq")
	return nil
}
