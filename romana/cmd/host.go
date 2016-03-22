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

	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// hostCmd represents the host commands
var hostCmd = &cli.Command{
	Use:   "host [add|show|list|remove]",
	Short: "Add, Remove or Show hosts for romana services.",
	Long: `Add, Remove or Show hosts for romana services.

host requires a subcommand, e.g. ` + "`romana host add`." + `

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
	hostCmd.AddCommand(hostAddCmd)
	hostCmd.AddCommand(hostShowCmd)
	hostCmd.AddCommand(hostListCmd)
	hostCmd.AddCommand(hostRemoveCmd)
}

var hostAddCmd = &cli.Command{
	Use:          "add",
	Short:        "Add a new host.",
	Long:         `Add a new host.`,
	RunE:         hostAdd,
	SilenceUsage: true,
}

var hostShowCmd = &cli.Command{
	Use:          "show [host name]",
	Short:        "Show details for a specific host.",
	Long:         `Show details for a specific host.`,
	RunE:         hostShow,
	SilenceUsage: true,
}

var hostListCmd = &cli.Command{
	Use:          "list",
	Short:        "List all hosts.",
	Long:         `List all hosts if no argument given else show a specific one.`,
	RunE:         hostList,
	SilenceUsage: true,
}

var hostRemoveCmd = &cli.Command{
	Use:          "remove",
	Short:        "Remove a host.",
	Long:         `Remove a host.`,
	RunE:         hostRemove,
	SilenceUsage: true,
}

func hostAdd(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Add a new host.")
	return nil
}

func hostShow(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Show host details.")
	return nil
}

func hostList(cmd *cli.Command, args []string) error {
	client, err := common.NewRestClient(rootURL, common.GetDefaultRestClientConfig())
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl(rootURL, "topology")
	if err != nil {
		return err
	}

	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return err
	}

	hostURL := index.Links.FindByRel("host-list")
	hosts := []common.HostMessage{}
	err = client.Get(hostURL, &hosts)
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		body, err := json.MarshalIndent(hosts, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(body))
	} else {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 0, '\t', 0)
		fmt.Println("Host List")
		fmt.Fprintln(w, "Id\t",
			"Host Name\t",
			"Host IP\t",
			"Romana IP\t")
		for _, host := range hosts {
			fmt.Fprintln(w, host.Id, "\t",
				host.Name, "\t",
				host.Ip, "\t",
				host.RomanaIp)
		}
		w.Flush()
	}

	return nil
}

func hostRemove(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Remove a host.")
	return nil
}
