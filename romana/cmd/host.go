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

	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// hostCmd represents the host commands
var hostCmd = &cli.Command{
	Use:   "host [add|show|list|remove]",
	Short: "Add, Remove or Show hosts for romana services.",
	Long: `Add, Remove or Show hosts for romana services.

host requires a subcommand, e.g. ` + "`romana host add`." + `

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
	Use:          "add [hostname][hostip][romana cidr][(optional)agent port]",
	Short:        "Add a new host.",
	Long:         `Add a new host.`,
	RunE:         hostAdd,
	SilenceUsage: true,
}

var hostShowCmd = &cli.Command{
	Use:          "show [hostname1][hostname2]...",
	Short:        "Show details for a specific host.",
	Long:         `Show details for a specific host.`,
	RunE:         hostShow,
	SilenceUsage: true,
}

var hostListCmd = &cli.Command{
	Use:          "list",
	Short:        "List all hosts.",
	Long:         `List all hosts.`,
	RunE:         hostList,
	SilenceUsage: true,
}

var hostRemoveCmd = &cli.Command{
	Use:          "remove [hostname|hostip]",
	Short:        "Remove a host.",
	Long:         `Remove a host.`,
	RunE:         hostRemove,
	SilenceUsage: true,
}

func hostAdd(cmd *cli.Command, args []string) error {
	if len(args) < 3 || len(args) > 4 {
		return UsageError(cmd,
			fmt.Sprintf("expected 3 or 4 arguments, saw %d: %s", len(args), args))
	}

	hostname := args[0]
	hostip := args[1]
	romanacidr := args[2]
	var agentport int
	if len(args) == 4 {
		var err error
		agentport, err = strconv.Atoi(args[3])
		if err != nil {
			return UsageError(cmd,
				fmt.Sprintf("Agent Port number error, saw %s", args[3]))
		}
	} else {
		agentport, _ = strconv.Atoi("9606")
	}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl("topology")
	if err != nil {
		return err
	}

	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return err
	}

	host := common.HostMessage{
		Name:      hostname,
		Ip:        hostip,
		RomanaIp:  romanacidr,
		AgentPort: agentport,
	}
	fmt.Printf("Host (%v) added successfully.\n", host)

	data := common.HostMessage{}
	err = client.Post(topologyURL+"/hosts", host, &data)
	if err != nil {
		fmt.Printf("Error adding host (%s).\n", hostname)
		return err
	}

	fmt.Printf("Host (%s) added successfully.\n", hostname)
	return nil
}

func hostShow(cmd *cli.Command, args []string) error {
	if len(args) < 1 {
		return UsageError(cmd,
			fmt.Sprintf("expected at-least 1 argument, saw none"))
	}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl( "topology")
	if err != nil {
		return err
	}

	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return err
	}

	hostURL := index.Links.FindByRel("host-list")
	data := []common.HostMessage{}
	hosts := []common.HostMessage{}
	err = client.Get(hostURL, &data)
	if err != nil {
		return err
	}

	for _, h := range data {
		for _, n := range args {
			if h.Name == n {
				hosts = append(hosts, h)
			}
		}
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
			"Romana CIDR\t",
			"Agent Port\t")
		for _, host := range hosts {
			fmt.Fprintln(w, host.Id, "\t",
				host.Name, "\t",
				host.Ip, "\t",
				host.RomanaIp, "\t",
				host.AgentPort, "\t")
		}
		w.Flush()
	}

	return nil
}

func hostList(cmd *cli.Command, args []string) error {
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig())
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
			"Romana CIDR\t",
			"Agent Port\t")
		for _, host := range hosts {
			fmt.Fprintln(w, host.Id, "\t",
				host.Name, "\t",
				host.Ip, "\t",
				host.RomanaIp, "\t",
				host.AgentPort, "\t")
		}
		w.Flush()
	}

	return nil
}

func hostRemove(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Remove a host.")
	return nil
}
