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

// Endpoint represents an endpoint (a VM, a Kubernetes Pod, etc.)
// that is to get an IP address.
type Endpoint struct {
	Ip           string         `json:"ip,omitempty"`
	TenantId     string         `json:"tenant_id,omitempty"`
	SegmentId    string         `json:"segment_id,omitempty"`
	HostId       string         `json:"host_id,omitempty"`
	Name         string         `json:"name,omitempty"`
	RequestToken sql.NullString `json:"request_token" sql:"unique"`
	// Ordinal number of this Endpoint in the host/tenant combination
	Seq uint64 `json:"-"`
	// Calculated effective sequence number of this Endpoint --
	// taking into account stride (endpoint space bits)
	// and alignment thereof. This is used in IP calculation.
	EffectiveSeq uint64 `json:"-"`
	// Whether it is in use (for purposes of reclaiming)
	InUse bool   `json:"-"`
	Id    uint64 `sql:"AUTO_INCREMENT",json:"-"`
}
type ipamStore struct {
	common.DbStore
}

// deleteEndpoint releases the IP(s) owned by the endpoint into assignable
// pool.
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

// addEndpoint allocates an IP address and stores it in the
// database.
func (ipamStore *ipamStore) addEndpoint(endpoint *Endpoint, upToEndpointIpInt uint64, stride uint) error {
	var err error
	tx := ipamStore.DbStore.Db.Begin()
	hostId := endpoint.HostId
	endpoint.InUse = true
	tenantId := endpoint.TenantId
	segId := endpoint.SegmentId
	filter := "host_id = ? AND tenant_id = ? AND segment_id = ? "
	// First, see if there is a formerly allocated IP already that has been released
	// (marked "in_use")
	where := filter + "AND in_use = 0"
	sel := "min(seq), ip"
	log.Printf("Calling SELECT %s FROM endpoints WHERE %s;", sel, fmt.Sprintf(strings.Replace(where, "?", "%s", 3), hostId, tenantId, segId))
	row := tx.Model(Endpoint{}).Where(where, hostId, tenantId, segId).Select(sel).Row()
	seq := sql.NullInt64{}
	var ip string
	row.Scan(&seq, &ip)
	log.Printf("minseq: %v, IP: %s", seq, ip)
	if seq.Valid {
		endpoint.Ip = ip
		tx = tx.Model(Endpoint{}).Where("ip = ?", ip).Update("in_use", true)
		err = common.MakeMultiError(tx.GetErrors())
		if err != nil {
			tx.Rollback()
			return err
		}
		tx.Commit()
		return nil
	}
	// Otherwise, find the MAX sequence available for this host/segment combination.
	// TODO can this be done in a single query?
	where = filter + "AND in_use = 1"
	sel = "ifnull(max(seq),-1)+1"
	log.Printf("Calling SELECT %s FROM endpoints WHERE %s;", sel, fmt.Sprintf(strings.Replace(where, "?", "%s", 3), hostId, tenantId, segId))
	row = tx.Model(Endpoint{}).Where(where, hostId, tenantId, segId).Select(sel).Row()
	seq = sql.NullInt64{}
	row.Scan(&seq)
	log.Printf("maxseq: %v", seq)

	endpoint.Seq = uint64(seq.Int64)

	log.Printf("New sequence is %d\n", endpoint.Seq)

	endpoint.EffectiveSeq = getEffectiveSeq(endpoint.Seq, stride)
	log.Printf("Effective sequence for seq %d (stride %d): %d\n", endpoint.Seq, stride, endpoint.EffectiveSeq)

	ipInt := upToEndpointIpInt | endpoint.EffectiveSeq
	endpoint.Ip = common.IntToIPv4(ipInt).String()
	tx = tx.Create(endpoint)
	log.Printf("IpamStore: Creating %v", endpoint)
	err = common.MakeMultiError(tx.GetErrors())
	if err != nil {
		log.Printf("Errors: %v", err)
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

// getEffectiveSeq gets effective sequence number of an Endpoint
// on a given host (see endpoint.EffectiveSeq).
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
	db.Model(&Endpoint{}).AddUniqueIndex("idx_tenant_segment_host_seq", "tenant_id", "segment_id", "host_id", "seq")
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}
