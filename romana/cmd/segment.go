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
	"errors"
	"fmt"
	"strconv"

	"github.com/romana/core/common"
	"github.com/romana/core/romana/romana"
	"github.com/romana/core/romana/util"
	"github.com/romana/core/tenant"

	cli "github.com/spf13/cobra"
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
}

var segmentAddCmd = &cli.Command{
	Use:          "add [tenantName][segmentName]",
	Short:        "Add a new segment.",
	Long:         `Add a new segment.`,
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
	romanaID, err := romana.GetTenantID(tnt)
	if err != nil {
		return errors.New("Romana Tenant doesn't exists: " + tnt)
	}
	romanaIDStr := strconv.FormatUint(romanaID, 10)

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
	if err != nil {
		return err
	}

	tenantURL, err := client.GetServiceUrl( "tenant")
	if err != nil {
		return err
	}

	data := tenant.Segment{Name: seg}
	segment := tenant.Segment{}
	err = client.Post(tenantURL+"/tenants/"+romanaIDStr+"/segments",
		data, &segment)
	if err != nil {
		return err
	}

	fmt.Printf("Tenant Segment (%s) added successfully.\n", seg)
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
