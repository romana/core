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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/romana/core/cli/util"
	"github.com/romana/core/common"
	"github.com/romana/core/common/api"

	"github.com/go-resty/resty"
	ms "github.com/mitchellh/mapstructure"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// topologyCmd represents the topology commands
var topologyCmd = &cli.Command{
	Use:   "topology [update|list]",
	Short: "Update or List topology for romana services.",
	Long: `Update or List topology for romana services.

topology requires a subcommand, e.g. ` + "`romana topology list`." + `

For more information, please check http://docs.romana.io
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
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)

		if resp.StatusCode() == http.StatusOK {
			var topology api.TopologyUpdateRequest
			err := json.Unmarshal(resp.Body(), &topology)
			if err == nil {
				fmt.Println("Networks")
				fmt.Fprint(w, "Name\tCIDR\tTenants\n")
				for _, n := range topology.Networks {
					fmt.Fprintf(w, "%s\t%s\t%v\n",
						n.Name,
						n.CIDR,
						n.Tenants,
					)
				}
				fmt.Fprint(w, "\n")
				for _, t := range topology.Topologies {
					fmt.Printf("Topology for Network/s: %s\n", t.Networks)
					fmt.Fprint(w, "Name\tCIDR\tNodes\n")
					for _, m := range t.Map {
						fmt.Fprintf(w, "%s\t%s\t", m.Name, m.CIDR)
						for _, n := range m.Groups {
							fmt.Fprintf(w, "%s(%s), ", n.Name, n.IP)
						}
						fmt.Fprint(w, "\n")
					}
					fmt.Fprint(w, "\n")
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

// topologyUpdate updates romana topology.
// The features supported are:
//  * Topology update through file
//  * Topology update while taking input from standard
//    input (STDIN) instead of a file
func topologyUpdate(cmd *cli.Command, args []string) error {
	var buf []byte
	var err error
	isFile := true

	if len(args) == 0 {
		isFile = false
		buf, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("cannot read 'STDIN': %s", err)
		}
	} else if len(args) != 1 {
		return util.UsageError(cmd,
			"TOPOLOGY FILE name or piped input from 'STDIN' expected.")
	}

	rootURL := config.GetString("RootURL")

	var topology api.TopologyUpdateRequest
	if isFile {
		pBuf, err := ioutil.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("file error: %s", err)
		}
		err = json.Unmarshal(pBuf, &topology)
		if err != nil {
			return err
		}
	} else {
		err = json.Unmarshal(buf, &topology)
		if err != nil {
			return err
		}
	}

	resp, err := resty.R().SetHeader("Content-Type", "application/json").
		SetBody(topology).Post(rootURL + "/topology")
	if err != nil {
		log.Printf("Error updating topology: %v\n", err)
		return err
	}

	if config.GetString("Format") == "json" {
		if string(resp.Body()) == "" || string(resp.Body()) == "null" {
			var h common.HttpError
			dc := &ms.DecoderConfig{TagName: "json", Result: &h}
			decoder, err := ms.NewDecoder(dc)
			if err != nil {
				return err
			}
			m := make(map[string]interface{})
			m["details"] = resp.Status()
			m["status_code"] = resp.StatusCode()
			err = decoder.Decode(m)
			if err != nil {
				return err
			}
			status, _ := json.MarshalIndent(h, "", "\t")
			fmt.Println(string(status))
		} else {
			JSONFormat(resp.Body(), os.Stdout)
		}
	} else {
		if resp.StatusCode() == http.StatusOK {
			fmt.Println("Topology updated successfully.")
		} else {
			fmt.Printf("Error upadting topology: %s\n", resp.Status())
		}
	}

	return nil
}
