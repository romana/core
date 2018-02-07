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

// blockCmd represents the block commands
var blockCmd = &cli.Command{
	Use:   "block [add|show|list|remove]",
	Short: "Add, Remove or Show blocks for romana services.",
	Long: `Add, Remove or Show blocks for romana services.

block requires a subcommand, e.g. ` + "`romana block list`." + `

For more information, please check http://romana.io
`,
}

func init() {
	blockCmd.AddCommand(blockAddCmd)
	blockCmd.AddCommand(blockShowCmd)
	blockCmd.AddCommand(blockListCmd)
	blockCmd.AddCommand(blockRemoveCmd)
}

var blockAddCmd = &cli.Command{
	Use:          "add [block CIDR][block host]",
	Short:        "Add a new block.",
	Long:         `Add a new block.`,
	RunE:         blockAdd,
	SilenceUsage: true,
}

var blockShowCmd = &cli.Command{
	Use:          "show [block name 1][block name 2]...",
	Short:        "Show details for a specific block.",
	Long:         `Show details for a specific block.`,
	RunE:         blockShow,
	SilenceUsage: true,
}

var blockListCmd = &cli.Command{
	Use:          "list",
	Short:        "List all blocks.",
	Long:         `List all blocks.`,
	RunE:         blockList,
	SilenceUsage: true,
}

var blockRemoveCmd = &cli.Command{
	Use:          "remove [block name]",
	Short:        "Remove a block.",
	Long:         `Remove a block.`,
	RunE:         blockRemove,
	SilenceUsage: true,
}

func blockAdd(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Add block/s.")
	return nil
}

func blockShow(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Show block details.")
	return nil
}

func blockList(cmd *cli.Command, args []string) error {
	rootURL := config.GetString("RootURL")
	resp, err := resty.R().Get(rootURL + "/blocks")
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		JSONFormat(resp.Body(), os.Stdout)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)

		if resp.StatusCode() == http.StatusOK {
			var blocks api.IPAMBlocksResponse
			err := json.Unmarshal(resp.Body(), &blocks)
			if err == nil {
				fmt.Println("Block List")
				fmt.Fprintf(w,
					"Block CIDR\tBlock Host\tRevision\t"+
						"Block Tenant\tBlock Segment\tBlock Allocated IP Count\n",
				)
				for _, block := range blocks.Blocks {
					fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\n",
						block.CIDR.String(),
						block.Host,
						block.Revision,
						block.Tenant,
						block.Segment,
						block.AllocatedIPCount,
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

func blockRemove(cmd *cli.Command, args []string) error {
	fmt.Println("Unimplemented: Remove a block.")
	return nil
}
