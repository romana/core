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

// Package openstack implements openstack API specific
// helper functions.
package openstack

import (
	"log"
	"os"

	"github.com/romana/core/romana/util"

	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack"
	"github.com/rackspace/gophercloud/openstack/identity/v2/tenants"
	"github.com/rackspace/gophercloud/pagination"
)

var (
	identityClient *gophercloud.ServiceClient
	networkClient  *gophercloud.ServiceClient
	computeClient  *gophercloud.ServiceClient
)

func getIdentityClient() (*gophercloud.ServiceClient, error) {
	var err error
	if identityClient == nil {
		identityClient, err = initIdentityClient()
		if err != nil {
			log.Println("Error: ", err)
			return nil, err
		}
	}
	return identityClient, nil
}

func getComputeClient() (*gophercloud.ServiceClient, error) {
	var err error
	if computeClient == nil {
		computeClient, err = initComputeClient()
		if err != nil {
			log.Println("Error: ", err)
			return nil, err
		}
	}
	return computeClient, nil
}

func getNetworkClient() (*gophercloud.ServiceClient, error) {
	var err error
	if networkClient == nil {
		networkClient, err = initNetworkClient()
		if err != nil {
			log.Println("Error: ", err)
			return nil, err
		}
	}
	return networkClient, nil
}

// initIdentityClient initializes openstack api using
// gophercloud which handles auth tokens keeping api calls
// simpler. Currently it uses environment variables for
// authenticating with openstack identity.
func initIdentityClient() (*gophercloud.ServiceClient, error) {
	opts, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		log.Println("Error fetching openstack env vars: ", err)
		return nil, err
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		log.Println("Error authenticating with openstack: ", err)
		return nil, err
	}
	return openstack.NewIdentityV2(provider), nil
}

// initComputeClient initializes openstack api using
// gophercloud which handles auth tokens keeping api calls
// simpler. Currently it uses environment variables for
// authenticating with openstack identity.
func initComputeClient() (*gophercloud.ServiceClient, error) {
	opts, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		log.Println("Error fetching openstack env vars: ", err)
		return nil, err
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		log.Println("Error authenticating with openstack: ", err)
		return nil, err
	}
	return openstack.NewComputeV2(provider, gophercloud.EndpointOpts{
		Name:   "compute",
		Region: os.Getenv("OS_REGION_NAME"),
	})
}

// initNetworkClient initializes openstack api using
// gophercloud which handles auth tokens keeping api calls
// simpler. Currently it uses environment variables for
// authenticating with openstack identity.
func initNetworkClient() (*gophercloud.ServiceClient, error) {
	opts, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		log.Println("Error fetching openstack env vars: ", err)
		return nil, err
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		log.Println("Error authenticating with openstack: ", err)
		return nil, err
	}
	return openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Name:   "neutron",
		Region: os.Getenv("OS_REGION_NAME"),
	})
}

// GetTenantName returns openstack tenant name corresponding
// to the UUID being used in romana tenants.
func GetTenantName(uuid string) (string, error) {
	var tenant string

	c, err := getIdentityClient()
	if err != nil {
		log.Println("Error getting Identity Client: ", err)
		return "", err
	}

	opts := tenants.ListOpts{Limit: 20}
	pager := tenants.List(c, &opts)
	// brute force the whole tenant list to get the name?
	pager.EachPage(
		func(page pagination.Page) (bool, error) {
			tenantList, _ := tenants.ExtractTenants(page)
			for _, t := range tenantList {
				// "t" is tenants.Tenant
				if t.ID == uuid {
					tenant = t.Name
					// stop iterating and return tenant.Name
					return false, nil
				}
			}
			return true, nil
		},
	)

	if tenant == "" {
		log.Println("Tenant (UUID: %s) not found.", uuid)
		return "", util.ErrTenantNotFound
	}

	return tenant, nil
}

// GetTenantList returns openstack tenant list.
func GetTenantList() ([]tenants.Tenant, error) {
	c, err := getIdentityClient()
	if err != nil {
		return nil, err
	}

	opts := tenants.ListOpts{}
	pager := tenants.List(c, &opts)
	page, err := pager.AllPages()
	if err == nil {
		return tenants.ExtractTenants(page)
	}
	return nil, err
}

// TenantExists returns true/false depending on
// openstack tenant name or uuid exists.
func TenantExists(name string) bool {
	var tenant bool

	c, err := getIdentityClient()
	if err != nil {
		log.Println("Error getting Identity Client: ", err)
		return false
	}

	opts := tenants.ListOpts{Limit: 20}
	pager := tenants.List(c, &opts)
	// brute force the whole tenant list to get tenant details?
	pager.EachPage(
		func(page pagination.Page) (bool, error) {
			tenantList, _ := tenants.ExtractTenants(page)
			for _, t := range tenantList {
				// "t" is tenants.Tenant
				if t.ID == name || t.Name == name {
					tenant = true
					// stop iterating and return tenant
					return false, nil
				}
			}
			return true, nil
		},
	)
	return tenant
}

// GetTenantUUID returns openstack tenant UUID corresponding to the name.
func GetTenantUUID(tenant string) (string, error) {
	var uuid string

	c, err := getIdentityClient()
	if err != nil {
		log.Println("Error getting Identity Client: ", err)
		return "", err
	}

	opts := tenants.ListOpts{Limit: 20}
	pager := tenants.List(c, &opts)
	// brute force the whole tenant list to get the name?
	pager.EachPage(
		func(page pagination.Page) (bool, error) {
			tenantList, _ := tenants.ExtractTenants(page)
			for _, t := range tenantList {
				// "t" is tenants.Tenant
				if t.Name == tenant {
					uuid = t.ID
					// stop iterating and return tenant.Name
					return false, nil
				}
			}
			return true, nil
		},
	)

	if uuid == "" {
		log.Println("Tenant (Name: %s) not found.", tenant)
		return "", util.ErrTenantNotFound
	}

	return uuid, nil
}

// CreateTenant creates openstack specific tenant
// corresponding to the name given.
func CreateTenant(name string) error {
	return util.ErrUnimplementedFeature
}
