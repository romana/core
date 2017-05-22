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
	"os"

	"github.com/romana/core/romana/util"
	log "github.com/romana/rlog"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/pagination"
)

var (
	identityClient *gophercloud.ServiceClient
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
	if opts.DomainID == "" && opts.DomainName == "" {
		opts.DomainName = os.Getenv("OS_PROJECT_DOMAIN_NAME")
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		log.Println("Error authenticating with openstack: ", err)
		return nil, err
	}
	client, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{
		Region: os.Getenv("OS_REGION_NAME"),
	})
	if err != nil {
		log.Println("Error creating identity client:", err)
		return nil, err
	}
	return client, nil
}

// GetTenantName returns openstack tenant name corresponding
// to the UUID being used in romana tenants.
func GetTenantName(uuid string) (string, error) {
	c, err := getIdentityClient()
	if err != nil {
		log.Println("Error getting Identity Client: ", err)
		return "", err
	}
	result := projects.Get(c, uuid, projects.GetOpts{})
	project, err := result.Extract()
	if err != nil {
		log.Printf("Error looking up name for uuid %s: %s.\n", uuid, err)
		return "", err
	}

	return project.Name, nil
}

// TenantExists returns true/false depending on
// openstack tenant name or uuid exists.
func TenantExists(uuidOrName string) bool {
	name, err := GetTenantName(uuidOrName)
	// intentional nil error check
	if err == nil {
		log.Printf("TenantExists: UUID %s resolved to name %s", uuidOrName, name)
		return true
	}
	uuid, err := GetTenantUUID(uuidOrName)
	if err == nil {
		log.Printf("TenantExists: name %s resolved to uuid %s", uuidOrName, uuid)
		return true
	}
	log.Printf("%s not found as uuid or name", uuidOrName)
	return false
}

// GetTenantUUID returns openstack tenant UUID
// corresponding to the given tenantName.
func GetTenantUUID(tenantName string) (string, error) {
	var uuid string

	c, err := getIdentityClient()
	if err != nil {
		log.Println("Error getting Identity Client: ", err)
		return "", err
	}

	pager := projects.List(c, projects.ListOpts{Name: tenantName})
	pager.EachPage(
		func(page pagination.Page) (bool, error) {
			projectList, _ := projects.ExtractProjects(page)
			for _, project := range projectList {
				if project.Name == tenantName {
					uuid = project.ID
					// stop iterating and return tenant.Name
					return false, nil
				}
			}
			return true, nil
		},
	)

	if uuid == "" {
		log.Printf("Tenant (Name: %s) not found.\n", tenantName)
		return "", util.ErrTenantNotFound
	}

	return uuid, nil
}

// CreateTenant creates openstack specific tenant
// corresponding to the name given.
func CreateTenant(name string) error {
	return util.ErrUnimplementedFeature
}
