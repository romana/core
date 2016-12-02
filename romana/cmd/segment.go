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
	"errors"
	"fmt"
	"strconv"

	"github.com/romana/core/common"
	"github.com/romana/core/romana/romana"
	"github.com/romana/core/romana/util"
	"github.com/romana/core/tenant"

	ms "github.com/mitchellh/mapstructure"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// segmentCmd represents the segment commands
var segmentCmd = &cli.Command{
	Use:   "segment [add|remove|list]",
	Short: "Add or Remove a segment.",
	Long: `Add or Remove a segment.

For more information, please check http://romana.io
`,
}

func init() {
	segmentCmd.AddCommand(segmentAddCmd)
	segmentCmd.AddCommand(segmentRemoveCmd)
	segmentCmd.AddCommand(segmentListCmd)
	segmentAddCmd.Flags().StringVarP(&externalID, "externalid", "i", "", "External ID")
}

var segmentAddCmd = &cli.Command{
	Use:   "add [tenantName][segmentName]",
	Short: "Add a new segment.",
	Long: `Add a new segment.

  --externalid <External ID>  # Create segment with a specific external ID mentioned here.`,
	RunE:         segmentAdd,
	SilenceUsage: true,
}

var segmentRemoveCmd = &cli.Command{
	Use:          "remove [tenantName][segmentName]",
	Short:        "Remove a specific segment.",
	Long:         `Remove a specific segment.`,
	RunE:         segmentRemove,
	SilenceUsage: true,
}

var segmentListCmd = &cli.Command{
	Use:          "list [tenantName][tenantName]...",
	Short:        "List segments for a specific tenant.",
	Long:         `List segments for a specific tenant.`,
	RunE:         segmentList,
	SilenceUsage: true,
}

func segmentAdd(cmd *cli.Command, args []string) error {
	if len(args) != 2 {
		return util.UsageError(cmd, "TENANT and SEGMENT name should be provided.")
	}

	tnt := args[0]
	seg := args[1]

	client, err := getRestClient()
	if err != nil {
		return err
	}

	romanaID, err := romana.GetTenantID(client, tnt)
	if err != nil {
		return errors.New("Romana Tenant doesn't exists: " + tnt)
	}
	romanaIDStr := strconv.FormatUint(romanaID, 10)

	tenantURL, err := client.GetServiceUrl("tenant")
	if err != nil {
		return err
	}

	data := tenant.Segment{Name: seg, ExternalID: externalID}
	var result map[string]interface{}
	err = client.Post(tenantURL+"/tenants/"+romanaIDStr+"/segments",
		data, &result)
	if err != nil {
		return err
	}

	_, tFound := result["name"]
	if !tFound {
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
			return fmt.Errorf("HTTP Error")
		}
		return fmt.Errorf(h.Error())
	}

	if config.GetString("Format") == "json" {
		segment := tenant.Segment{}
		dc := &ms.DecoderConfig{TagName: "json", Result: &segment}
		decoder, err := ms.NewDecoder(dc)
		if err != nil {
			return err
		}
		err = decoder.Decode(result)
		if err != nil {
			return err
		}
		body, err := json.MarshalIndent(segment, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(body))
	} else {
		fmt.Printf("Tenant Segment (%s) added successfully.\n", seg)
	}
	return nil
}

func segmentRemove(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Remove a specific segment.")
	return nil
}

func segmentList(cmd *cli.Command, args []string) error {
	if len(args) < 1 {
		return util.UsageError(cmd, "TENANT name should be provided.")
	}

	tenantShow(cmd, args)
	return nil
}
