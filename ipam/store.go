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
	TenantID     string         `json:"tenant_id,omitempty"`
	SegmentID    string         `json:"segment_id,omitempty"`
	HostId       string         `json:"host_id,omitempty"`
	Name         string         `json:"name,omitempty"`
	RequestToken sql.NullString `json:"request_token" sql:"unique"`
	// Ordinal number of this Endpoint in the host/tenant combination
	NetworkID uint64 `json:"-"`
	// Calculated effective network ID of this Endpoint --
	// taking into account stride (endpoint space bits)
	// and alignment thereof. This is used in IP calculation.
	EffectiveNetworkID uint64 `json:"-"`
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
		return Endpoint{}, common.NewError404("endpoint", ip)
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
func (ipamStore *ipamStore) addEndpoint(endpoint *Endpoint, upToEndpointIpInt uint64, dc common.Datacenter) error {

	var err error
	tx := ipamStore.DbStore.Db.Begin()

	if endpoint.RequestToken.Valid && endpoint.RequestToken.String != "" {
		var existingEndpoints []Endpoint
		var count int
		tx.Where("request_token = ?", endpoint.RequestToken.String).Find(&existingEndpoints).Count(&count)
		err = common.GetDbErrors(tx)
		if err != nil {
			log.Printf("IPAM Errors 1: %v", err)
			tx.Rollback()
			return err
		}
		if count > 0 {
			// This will only be 1, because of unique constraint.
			tx.Rollback()
			log.Printf("Found existing %s: %+v", endpoint.RequestToken.String, existingEndpoints[0])
			endpoint.EffectiveNetworkID = existingEndpoints[0].EffectiveNetworkID
			endpoint.HostId = existingEndpoints[0].HostId
			endpoint.Id = existingEndpoints[0].Id
			endpoint.InUse = existingEndpoints[0].InUse
			endpoint.Name = existingEndpoints[0].Name
			endpoint.NetworkID = existingEndpoints[0].NetworkID
			endpoint.RequestToken = existingEndpoints[0].RequestToken
			endpoint.SegmentID = existingEndpoints[0].SegmentID
			endpoint.TenantID = existingEndpoints[0].TenantID
			return nil
		}
	}

	hostId := endpoint.HostId
	endpoint.InUse = true
	tenantId := endpoint.TenantID
	segId := endpoint.SegmentID
	filter := "host_id = ? AND tenant_id = ? AND segment_id = ? "

	var sel string
	// First, find the MAX network ID available for this host/segment combination.
	sel = "IFNULL(MAX(network_id),-1)+1"
	log.Printf("IpamStore: Calling SELECT %s FROM endpoints WHERE %s;", sel, fmt.Sprintf(strings.Replace(filter, "?", "%s", 3), hostId, tenantId, segId))
	row := tx.Model(Endpoint{}).Where(filter, hostId, tenantId, segId).Select(sel).Row()
	err = common.GetDbErrors(tx)
	if err != nil {
		log.Printf("IPAM Errors 2: %v", err)
		tx.Rollback()
		return err
	}

	netID := sql.NullInt64{}
	row.Scan(&netID)
	err = common.GetDbErrors(tx)
	if err != nil {
		log.Printf("IPAM Errors 3: %v", err)
		tx.Rollback()
		return err
	}

	log.Printf("IpamStore: max net ID: %v", netID)

	maxEffNetID := uint64(1<<(dc.EndpointSpaceBits+dc.EndpointBits) - 1)

	// Does this exceed max bits?
	endpoint.NetworkID = uint64(netID.Int64)
	endpoint.EffectiveNetworkID = getEffectiveNetworkID(endpoint.NetworkID, dc.EndpointSpaceBits)
	if endpoint.EffectiveNetworkID <= maxEffNetID {
		// Does not exceed max bits, all good.
		//		log.Printf("IpamStore: Effective network ID for network ID %d (stride %d): %d\n", endpoint.NetworkID, dc.EndpointSpaceBits, endpoint.EffectiveNetworkID)
		ipInt := upToEndpointIpInt | endpoint.EffectiveNetworkID
		//		log.Printf("IpamStore: %d | %d = %d", upToEndpointIpInt, endpoint.EffectiveNetworkID, ipInt)
		endpoint.Ip = common.IntToIPv4(ipInt).String()
		tx = tx.Create(endpoint)
		err = common.GetDbErrors(tx)
		if err != nil {
			log.Printf("IPAM Errors 4: %v", err)
			tx.Rollback()
			return err
		}
		tx.Commit()
		return nil
	}

	// Out of bits, see if we can reuse an earlier allocated address...
	log.Printf("IpamStore: New effective network ID is %d, exceeds maximum %d\n", endpoint.EffectiveNetworkID, maxEffNetID)
	// See if there is a formerly allocated IP already that has been released
	// (marked "in_use")
	sel = "MIN(network_id), ip"
	log.Printf("IpamStore: Calling SELECT %s FROM endpoints WHERE %s;", sel, fmt.Sprintf(strings.Replace(filter+"AND in_use = 0", "?", "%s", 3), hostId, tenantId, segId))
	// In containerized setup, not using group by leads to failure due to
	// incompatible sql mode, thus use "GROUP BY network_id, ip" to avoid
	// this failure.
	row = tx.Model(Endpoint{}).Where(filter+"AND in_use = 0", hostId, tenantId, segId).Select(sel).Group("ip").Row()
	err = common.GetDbErrors(tx)
	if err != nil {
		log.Printf("IPAM Errors 5: %v", err)
		tx.Rollback()
		return err
	}
	netID = sql.NullInt64{}
	var ip string
	row.Scan(&netID, &ip)
	err = common.GetDbErrors(tx)
	if err != nil {
		log.Printf("IPAM Errors 6: %v", err)
		tx.Rollback()
		return err
	}
	if netID.Valid {
		endpoint.Ip = ip
		tx = tx.Model(Endpoint{}).Where("ip = ?", ip).Update("in_use", true)
		err = common.GetDbErrors(tx)
		if err != nil {
			log.Printf("IPAM Errors 7: %v", err)
			tx.Rollback()
			return err
		}
		tx.Commit()
		return nil
	}
	tx.Rollback()
	return common.NewError("Out of IP addresses.")

}

// getEffectiveNetworkID gets effective number of an Endpoint
// on a given host (see endpoint.EffectiveNetworkID).
func getEffectiveNetworkID(EndpointNetworkID uint64, stride uint) uint64 {
	var effectiveEndpointNetworkID uint64
	// We start with 3 because we reserve 1 for gateway
	// and 2 for DHCP.
	effectiveEndpointNetworkID = 3 + (1<<stride)*EndpointNetworkID
	return effectiveEndpointNetworkID
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
	db.Model(&Endpoint{}).AddUniqueIndex("idx_tenant_segment_host_network_id", "tenant_id", "segment_id", "host_id", "network_id")
	db.Model(&Endpoint{}).AddUniqueIndex("idx_ip", "ip")
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	return nil
}
