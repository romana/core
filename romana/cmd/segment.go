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
	rc "github.com/romana/core/romana/client"
	"github.com/romana/core/tenant"

	"github.com/spf13/cobra"
)

// segmentCmd represents the segment commands
var segmentCmd = &cobra.Command{
	Use:   "segment [add|remove]",
	Short: "Add or Remove a segment.",
	Long: `Add or Remove a segment.

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
	segmentCmd.AddCommand(segmentAddCmd)
	segmentCmd.AddCommand(segmentRemoveCmd)
}

var segmentAddCmd = &cobra.Command{
	Use:          "add [tenant name] [segment name]",
	Short:        "Add a new segment.",
	Long:         `Add a new segment.`,
	RunE:         segmentAdd,
	SilenceUsage: true,
}

var segmentRemoveCmd = &cobra.Command{
	Use:          "remove",
	Short:        "Remove a specific segment.",
	Long:         `Remove a specific segment.`,
	RunE:         segmentRemove,
	SilenceUsage: true,
}

func segmentAdd(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return UsageError(cmd, "TENANT and SEGMENT name should be provided.")
	}

	tnt := args[0]
	seg := args[1]
	tenantUUID, err := rc.GetTenantUUID(tnt)
	if err != nil {
		return errors.New("Openstack Tenant doesn't exists: " + tnt)
	}

	romanaID, err := getRomanaTenantID(tenantUUID)
	if err != nil {
		return errors.New("Romana Tenant doesn't exists: " + tnt)
	}
	romanaIDStr := strconv.FormatUint(romanaID, 10)

	client, err := common.NewRestClient(rootURL, common.GetDefaultRestClientConfig())
	if err != nil {
		return err
	}

	tenantURL, err := client.GetServiceUrl(rootURL, "tenant")
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

func segmentRemove(cmd *cobra.Command, args []string) error {
	fmt.Println("Unimplemented: Remove a specific segment.")
	return nil
}
