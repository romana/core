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
	"strconv"
	"text/tabwriter"

	"github.com/romana/core/common"
	"github.com/romana/core/romana/adaptor"
	"github.com/romana/core/tenant"

	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// tenantData holds tenant information received from tenant
// service and its corresponding name received from adaptors.
type tenantData struct {
	Tenant   tenant.Tenant
	Name     string
	Segments []tenant.Segment
}

// tenantCmd represents the tenant commands
var tenantCmd = &cli.Command{
	Use:   "tenant [create|delete|show|list]",
	Short: "Create, Delete, Show or List Tenant Details.",
	Long: `Create, Delete, Show or List Tenant Details.

tenant requires a subcommand, e.g. ` + "`romana tenant create`." + `

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
	Use:          "create [tenantname]",
	Short:        "Create a new tenant.",
	Long:         `Create a new tenant.`,
	RunE:         tenantCreate,
	SilenceUsage: true,
}

var tenantShowCmd = &cli.Command{
	Use:          "show [tenantname1][tenantname2]...",
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
	if len(args) < 1 {
		return UsageError(cmd,
			fmt.Sprintf("expected at-least 1 argument, saw none"))
	}

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

	tenants := []tenantData{}
	for _, tnt := range args {
		if !adaptor.TenantExists(tnt) {
			// uncomment this once creating tenant for all
			// platforms are ready. Till then tenants needs
			// to be manually created for every platform and
			// then created using romana command line tools.
			// if adaptor.CreateTenant(tnt) != nil {
			return err
			// }
		}
		tntUUID, err := adaptor.GetTenantUUID(tnt)
		if err != nil {
			return err
		}
		data := tenant.Tenant{Name: tntUUID}
		result := tenant.Tenant{}
		err = client.Post(tenantURL+"/tenants", data, &result)
		if err != nil {
			return err
		}
		tenants = append(tenants, tenantData{result, tnt, []tenant.Segment{}})
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
		fmt.Println("New Tenant(s) Added:")
		fmt.Fprintln(w, "Id\t",
			"Tenant UUID\t",
			"Tenant Name\t",
		)
		for _, t := range tenants {
			fmt.Fprintf(w, "%d \t %s \t %s \t", t.Tenant.Id,
				t.Tenant.Name, t.Name)
			fmt.Fprintf(w, "\n")
		}
		w.Flush()
	}

	return nil
}

func tenantShow(cmd *cli.Command, args []string) error {
	if len(args) < 1 {
		return UsageError(cmd,
			fmt.Sprintf("expected at-least 1 argument, saw none"))
	}

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

	data := []tenant.Tenant{}
	tenants := []tenantData{}
	err = client.Get(tenantURL+"/tenants", &data)
	if err != nil {
		return err
	}

	for _, t := range data {
		for _, n := range args {
			name, _ := adaptor.GetTenantName(t.Name)
			if t.Name == n || name == n {
				seg := []tenant.Segment{}
				tIDStr := strconv.FormatUint(t.Id, 10)
				err = client.Get(tenantURL+"/tenants/"+tIDStr+"/segments", &seg)
				if err != nil {
					return err
				}
				tenants = append(tenants, tenantData{t, name, seg})
			}
		}
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
		fmt.Fprintln(w, "Id\t",
			"Tenant UUID\t",
			"Tenant Name\t",
			"Segments", "\t",
		)
		for _, t := range tenants {
			fmt.Fprintf(w, "%d \t %s \t %s \t", t.Tenant.Id,
				t.Tenant.Name, t.Name)
			for _, s := range t.Segments {
				fmt.Fprintf(w, "%s, ", s.Name)
			}
			fmt.Fprintf(w, "\n")
		}
		w.Flush()
	}

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

	data := []tenant.Tenant{}
	tenants := []tenantData{}
	err = client.Get(tenantURL+"/tenants", &data)
	if err != nil {
		return err
	}

	for _, t := range data {
		name, _ := adaptor.GetTenantName(t.Name)
		tenants = append(tenants, tenantData{t, name, []tenant.Segment{}})
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
			"Tenant Name\t",
		)
		for _, t := range tenants {
			fmt.Fprintln(w, t.Tenant.Id, "\t",
				t.Tenant.Name, "\t", t.Name, "\t",
			)
		}
		w.Flush()
	}

	return nil
}

func tenantDelete(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Delete a specific tenant.")
	return nil
}
