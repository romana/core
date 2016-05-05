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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/romana/core/common"
	"github.com/romana/core/romana/adaptor"
	"github.com/romana/core/romana/util"
	"github.com/romana/core/tenant"

	ms "github.com/mitchellh/mapstructure"
	"github.com/pborman/uuid"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// tenantData holds tenant information received from tenant
// service and its corresponding name received from adaptors.
type tenantData struct {
	Tenant   tenant.Tenant
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

// tenantCreate accepts tenant names as arguments for
// creating new tenants for platform being set in
// config file (~/.romana.yaml) or via command line
// flags.
func tenantCreate(cmd *cli.Command, args []string) error {
	if len(args) < 1 {
		return util.UsageError(cmd,
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

	tenants := []tenant.Tenant{}
	for _, tnt := range args {
		// uncomment this once creating tenant for all
		// platforms are ready. Till then tenants needs
		// to be manually created for every platform and
		// then created using romana command line tools.
		// if adaptor.CreateTenant(tnt) != nil {
		// 	return err
		// }
		// adaptor.GetTenantUUID below wouldn't be needed once
		// adaptor.CreateTenant is supported.
		tntUUID, err := adaptor.GetTenantUUID(tnt)
		if err != nil {
			switch err {
			case util.ErrUnimplementedFeature:
				// kubernetes doesnt support tenants yet so
				// exception for kubernetes till CreateTenant,
				// GetTenantUUID, etc are supported for it.
				tntUUID = hex.EncodeToString(uuid.NewRandom())
			default:
				return err
			}
		}

		data := tenant.Tenant{Name: tnt, ExternalID: tntUUID}
		var result map[string]interface{}
		err = client.Post(tenantURL+"/tenants", data, &result)
		if err != nil {
			return err
		}
		_, tFound := result["ExternalID"]
		if tFound {
			var t tenant.Tenant
			err := ms.Decode(result, &t)
			if err != nil {
				return err
			}
			tenants = append(tenants, t)
		} else {
			var h common.HttpError
			dc := &ms.DecoderConfig{TagName: "json", Result: &h}
			decoder, err := ms.NewDecoder(dc)
			if err != nil {
				return err
			}
			err = decoder.Decode(result)
			if err != nil {
				return err
			}
			if config.GetString("Format") == "json" {
				status, _ := json.MarshalIndent(h, "", "\t")
				fmt.Println(string(status))
				return fmt.Errorf("HTTP Error.")
			} else {
				return fmt.Errorf("HTTP Error.\nStatus Code: %d\n"+
					"Status Text:%s\nMessage:%s",
					h.StatusCode, h.StatusText, h.Message)
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
		fmt.Println("New Tenant(s) Added:")
		fmt.Fprintln(w, "Id\t",
			"Tenant Name\t",
			"External ID\t",
		)
		for _, t := range tenants {
			fmt.Fprintf(w, "%d \t %s \t %s \t", t.ID,
				t.Name, t.ExternalID)
			fmt.Fprintf(w, "\n")
		}
		w.Flush()
	}

	return nil
}

// tenantShow displays tenant details using tenant name
// or tenant external id as input.
func tenantShow(cmd *cli.Command, args []string) error {
	if len(args) < 1 {
		return util.UsageError(cmd,
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
			if t.Name == n || t.ExternalID == n {
				seg := []tenant.Segment{}
				err = client.Get(tenantURL+"/tenants/"+t.ExternalID+"/segments", &seg)
				if err != nil {
					return err
				}
				tenants = append(tenants, tenantData{t, seg})
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
		fmt.Fprintln(w, "ID\t",
			"Tenant Name\t",
			"External ID\t",
			"Segments", "\t",
		)
		for _, t := range tenants {
			fmt.Fprintf(w, "%d \t %s \t %s \t", t.Tenant.ID,
				t.Tenant.Name, t.Tenant.ExternalID)
			for _, s := range t.Segments {
				fmt.Fprintf(w, "%s, ", s.Name)
			}
			fmt.Fprintf(w, "\n")
		}
		w.Flush()
	}

	return nil
}

// tenantList displays tenant list in either json or
// tablular format depending on commanf line flags or
// config file options.
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
			"Tenant Name\t",
			"External ID\t",
		)
		for _, t := range tenants {
			fmt.Fprintln(w, t.ID, "\t",
				t.Name, "\t",
				t.ExternalID, "\t",
			)
		}
		w.Flush()
	}

	return nil
}

// tenantDelete takes tenant name as input for deleting a specific
// romana tenant, the equivalent tenant for specific platform
// still needs to be deleted manually until handled here via
// adaptor.
func tenantDelete(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Delete a specific tenant.")
	return nil
}
