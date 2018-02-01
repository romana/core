// Copyright (c) 2017 Pani Networks
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

package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/romana/core/common/api"

	"github.com/go-resty/resty"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// networkCmd represents the network commands
var networkCmd = &cli.Command{
	Use:   "network [add|show|list|remove]",
	Short: "Add, Remove or Show networks for romana services.",
	Long: `Add, Remove or Show networks for romana services.

network requires a subcommand, e.g. ` + "`romana network add`." + `

For more information, please check http://romana.io
`,
}

func init() {
	networkCmd.AddCommand(networkAddCmd)
	networkCmd.AddCommand(networkShowCmd)
	networkCmd.AddCommand(networkListCmd)
	networkCmd.AddCommand(networkRemoveCmd)
}

var networkAddCmd = &cli.Command{
	Use:          "add [network name][network cidr]",
	Short:        "Add a new network.",
	Long:         `Add a new network.`,
	RunE:         networkAdd,
	SilenceUsage: true,
}

var networkShowCmd = &cli.Command{
	Use:          "show [network name 1][network name 2]...",
	Short:        "Show details for a specific network.",
	Long:         `Show details for a specific network.`,
	RunE:         networkShow,
	SilenceUsage: true,
}

var networkListCmd = &cli.Command{
	Use:          "list",
	Short:        "List all networks.",
	Long:         `List all networks.`,
	RunE:         networkList,
	SilenceUsage: true,
}

var networkRemoveCmd = &cli.Command{
	Use:          "remove [network name]",
	Short:        "Remove a network.",
	Long:         `Remove a network.`,
	RunE:         networkRemove,
	SilenceUsage: true,
}

func networkAdd(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Add network/s.")
	return nil
}

func networkShow(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Show network details.")
	return nil
}

func networkList(cmd *cli.Command, args []string) error {
	rootURL := config.GetString("RootURL")
	resp, err := resty.R().Get(rootURL + "/networks")
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		JSONFormat(resp.Body(), os.Stdout)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)

		if resp.StatusCode() == http.StatusOK {
			var networks []api.IPAMNetworkResponse
			err := json.Unmarshal(resp.Body(), &networks)
			if err == nil {
				fmt.Println("Network List")
				fmt.Fprintf(w, "Network Name\tNetwork CIDR\tRevision\n")
				for _, net := range networks {
					fmt.Fprintf(w, "%s\t%s\t%d\n",
						net.Name,
						net.CIDR.String(),
						net.Revision,
					)
				}
			} else {
				fmt.Printf("Error: %s \n", err)
			}
		} else {
			var e Error
			json.Unmarshal(resp.Body(), &e)

			fmt.Println("Host Error")
			fmt.Fprintf(w, "Fields\t%s\n", e.Fields)
			fmt.Fprintf(w, "Message\t%s\n", e.Message)
			fmt.Fprintf(w, "Status\t%d\n", resp.StatusCode())
		}
		w.Flush()
	}

	return nil
}

func networkRemove(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Remove a network.")
	return nil
}
