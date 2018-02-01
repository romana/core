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
	Use:          "add [hostip][(optional)romana cidr][(optional)agent port]",
	Short:        "Add a new host.",
	Long:         `Add a new host.`,
	RunE:         hostAdd,
	SilenceUsage: true,
}

var hostShowCmd = &cli.Command{
	Use:          "show [hostip1][hostip2]...",
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
	Use:          "remove [hostip]",
	Short:        "Remove a host.",
	Long:         `Remove a host.`,
	RunE:         hostRemove,
	SilenceUsage: true,
}

func hostAdd(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Add host/s.")
	return nil
}

func hostShow(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Show host details.")
	return nil
}

func hostList(cmd *cli.Command, args []string) error {
	rootURL := config.GetString("RootURL")
	resp, err := resty.R().Get(rootURL + "/hosts")
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		JSONFormat(resp.Body(), os.Stdout)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)

		if resp.StatusCode() == http.StatusOK {
			var hosts api.HostList
			err := json.Unmarshal(resp.Body(), &hosts)
			if err == nil {
				fmt.Println("Host List")
				fmt.Fprintf(w, "Host IP\tHost Name\n")
				for _, host := range hosts.Hosts {
					fmt.Fprintf(w, "%s\t%s\n",
						host.IP.String(),
						host.Name,
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

func hostRemove(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Remove a host.")
	return nil
}
