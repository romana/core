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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/romana/core/common"
	rc "github.com/romana/core/romana/client"
	"github.com/romana/core/tenant"

	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// tenantCmd represents the tenant commands
var tenantCmd = &cli.Command{
	Use:   "tenant [create|delete|show|list]",
	Short: "Create, Delete, Show or List Tenant Details.",
	Long: `Create, Delete, Show or List Tenant Details.

tenant requires a subcommand, e.g. ` + "`romana tenant create`." + `

Romana is a new Software Defined Network solution specifically
designed for Cloud Native applications. Romana allows multi-tenant
cloud computing networks for OpenStack, Docker and Kubernetes to
be built without encapsulation or a virtual network overlay.

Romana networks are less expensive to build, easier to operate
and deliver higher performance than networks built using
alternative overlay based SDN designs.

For more information, please check http://romana.io
`,
}

func init() {
	tenantCmd.AddCommand(tenantCreateCmd)
	tenantCmd.AddCommand(tenantShowCmd)
	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantDeleteCmd)
}

var tenantCreateCmd = &cli.Command{
	Use:          "create",
	Short:        "Create a new tenant.",
	Long:         `Create a new tenant.`,
	RunE:         tenantCreate,
	SilenceUsage: true,
}

var tenantShowCmd = &cli.Command{
	Use:          "show",
	Short:        "Show tenant details.",
	Long:         `Show tenant details.`,
	RunE:         tenantShow,
	SilenceUsage: true,
}

var tenantListCmd = &cli.Command{
	Use:          "list",
	Short:        "List all tenants.",
	Long:         `List all tenants.`,
	RunE:         tenantList,
	SilenceUsage: true,
}

var tenantDeleteCmd = &cli.Command{
	Use:          "delete",
	Short:        "Delete a specific tenant.",
	Long:         `Delete a specific tenant.`,
	RunE:         tenantDelete,
	SilenceUsage: true,
}

func tenantCreate(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Create a new tenant.")
	return nil
}

func tenantShow(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Show tenant details.")
	return nil
}

func tenantList(cmd *cli.Command, args []string) error {
	rootURL := config.GetString("RootURL")

	client, err := common.NewRestClient(rootURL,
		common.GetDefaultRestClientConfig())
	if err != nil {
		return err
	}

	tenantURL, err := client.GetServiceUrl(rootURL, "tenant")
	if err != nil {
		return err
	}

	tenants := []tenant.Tenant{}
	err = client.Get(tenantURL+"/tenants", &tenants)
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		body, err := json.MarshalIndent(tenants, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(body))
	} else {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 0, '\t', 0)
		fmt.Println("Tenant List")
		fmt.Fprintln(w, "Id\t",
			"Tenant UUID\t",
			"Tenant Name")
		for _, tenant := range tenants {
			t, _ := rc.GetTenantName(tenant.Name)
			fmt.Fprintln(w, tenant.Id, "\t",
				tenant.Name, "\t", t)
		}
		w.Flush()
	}

	return nil
}

func tenantDelete(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Delete a specific tenant.")
	return nil
}
