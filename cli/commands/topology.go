// Copyright (c) 2018 Pani Networks
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

// topologyCmd represents the topology commands
var topologyCmd = &cli.Command{
	Use:   "topology [update|list]",
	Short: "Update or List topology for romana services.",
	Long: `Update or List topology for romana services.

topology requires a subcommand, e.g. ` + "`romana topology list`." + `

For more information, please check http://romana.io
`,
}

func init() {
	topologyCmd.AddCommand(topologyListCmd)
	topologyCmd.AddCommand(topologyUpdateCmd)
}

var topologyListCmd = &cli.Command{
	Use:          "list",
	Short:        "List romana topology.",
	Long:         `List romana topology.`,
	RunE:         topologyList,
	SilenceUsage: true,
}

var topologyUpdateCmd = &cli.Command{
	Use:          "update [file name]",
	Short:        "Update romana topology.",
	Long:         `Update romana topology.`,
	RunE:         topologyUpdate,
	SilenceUsage: true,
}

func topologyList(cmd *cli.Command, args []string) error {
	rootURL := config.GetString("RootURL")
	resp, err := resty.R().Get(rootURL + "/topology")
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		JSONFormat(resp.Body(), os.Stdout)
	} else {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 0, '\t', 0)

		if resp.StatusCode() == http.StatusOK {
			var topology api.TopologyUpdateRequest
			err := json.Unmarshal(resp.Body(), &topology)
			if err == nil {
				fmt.Println("Networks")
				fmt.Fprintln(w,
					"Name\t",
					"CIDR\t",
					"Tenants\t")
				for _, n := range topology.Networks {
					fmt.Fprintln(w,
						n.Name, "\t",
						n.CIDR, "\t",
						n.Tenants, "\t")
				}
				fmt.Fprintln(w, "")
				for _, t := range topology.Topologies {
					fmt.Printf("Topology for Network/s: %s\n", t.Networks)
					fmt.Fprintln(w,
						"Name\t",
						"CIDR\t",
						"Nodes\t")
					for _, m := range t.Map {
						fmt.Fprintf(w,
							"%s\t%s\t",
							m.Name,
							m.CIDR)
						for _, n := range m.Groups {
							fmt.Fprintf(w,
								"%s(%s), ",
								n.Name,
								n.IP)
						}
						fmt.Fprintln(w, "")
					}
					fmt.Fprintln(w, "")
				}
			} else {
				fmt.Printf("Error: %s \n", err)
			}
		} else {
			var e Error
			json.Unmarshal(resp.Body(), &e)

			fmt.Println("Host Error")
			fmt.Fprintln(w, "Fields\t", e.Fields)
			fmt.Fprintln(w, "Message\t", e.Message)
			fmt.Fprintln(w, "Status\t", resp.StatusCode())
		}
		w.Flush()
	}

	return nil
}

func topologyUpdate(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Update romana topology.")
	return nil
}
