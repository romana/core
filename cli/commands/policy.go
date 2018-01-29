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
	"io/ioutil"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/romana/core/cli/util"
	"github.com/romana/core/common"
	"github.com/romana/core/common/api"

	"github.com/go-resty/resty"
	ms "github.com/mitchellh/mapstructure"
	log "github.com/romana/rlog"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// Policies structure is used to keep track of
// security policies and their status, as to if
// they were applied successfully or not.
type Policies struct {
	SecurityPolicies    []api.Policy
	AppliedSuccessfully []bool
}

// policyCmd represents the policy commands
var policyCmd = &cli.Command{
	Use:   "policy [add|show|list|remove]",
	Short: "Add, Remove or Show policies for romana services.",
	Long: `Add, Remove or Show policies for romana services.

For more information, please check http://romana.io
`,
}

func init() {
	policyCmd.AddCommand(policyAddCmd)
	policyCmd.AddCommand(policyRemoveCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyShowCmd)
}

var policyAddCmd = &cli.Command{
	Use:   "add [policyFile][STDIN]",
	Short: "Add a new policy.",
	Long: `Add a new policy.

Romana policies can be added for a specific network
using the policyFile provided or through input pipe.
The features supported are:
 * Policy addition through file with single policy in it
 * Policy addition through file with multiple policies
   in it
 * Both the above formats but taking input from standard
   input (STDIN) instead of a file
 * Tabular and json output for indication of policy
   addition
`,
	RunE:         policyAdd,
	SilenceUsage: true,
}

var policyRemoveCmd = &cli.Command{
	Use:          "remove [policyID]",
	Short:        "Remove a specific policy.",
	Long:         `Remove a specific policy.`,
	RunE:         policyRemove,
	SilenceUsage: true,
}

var policyListCmd = &cli.Command{
	Use:          "list",
	Short:        "List all policies.",
	Long:         `List all policies.`,
	RunE:         policyList,
	SilenceUsage: true,
}

var policyShowCmd = &cli.Command{
	Use:          "show [PolicyID]",
	Short:        "Show details about a specific policy using policyID.",
	Long:         `Show details about a specific policy using policyID.`,
	RunE:         policyShow,
	SilenceUsage: true,
}

// policyAdd adds romana policy for a specific tenant
// using the policyFile provided or through input pipe.
// The features supported are:
//  * Policy addition through file with single policy in it
//  * Policy addition through file with multiple policies
//    in it
//  * Both the above formats but taking input from standard
//    input (STDIN) instead of a file
//  * Tabular and json output for indication of policy
//    addition
func policyAdd(cmd *cli.Command, args []string) error {
	var buf []byte
	var policyFile string
	var err error
	isFile := true
	isJSON := config.GetString("Format") == "json"

	if len(args) == 0 {
		isFile = false
		buf, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			util.UsageError(cmd,
				"POLICY FILE name or piped input from 'STDIN' expected.")
			return fmt.Errorf("Cannot read 'STDIN': %s\n", err)
		}
	} else if len(args) != 1 {
		return util.UsageError(cmd,
			"POLICY FILE name or piped input from 'STDIN' expected.")
	}

	if isFile {
		policyFile = args[0]
	}

	rootURL := config.GetString("RootURL")

	reqPolicies := Policies{}
	if isFile {
		pBuf, err := ioutil.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("File error: %s\n", err)
		}
		err = json.Unmarshal(pBuf, &reqPolicies.SecurityPolicies)
		if err != nil || len(reqPolicies.SecurityPolicies) == 0 {
			reqPolicies.SecurityPolicies = make([]api.Policy, 1)
			err = json.Unmarshal(pBuf, &reqPolicies.SecurityPolicies[0])
			if err != nil {
				return err
			}
		}
	} else {
		err = json.Unmarshal(buf, &reqPolicies.SecurityPolicies)
		if err != nil || len(reqPolicies.SecurityPolicies) == 0 {
			reqPolicies.SecurityPolicies = make([]api.Policy, 1)
			err = json.Unmarshal(buf, &reqPolicies.SecurityPolicies[0])
			if err != nil {
				return err
			}
		}
	}

	result := make([]map[string]interface{}, len(reqPolicies.SecurityPolicies))
	reqPolicies.AppliedSuccessfully = make([]bool, len(reqPolicies.SecurityPolicies))
	for i, pol := range reqPolicies.SecurityPolicies {
		reqPolicies.AppliedSuccessfully[i] = false
		r, err := resty.R().SetHeader("Content-Type", "application/json").
			SetBody(pol).Post(rootURL + "/policies")
		m := make(map[string]interface{})
		m["details"] = r.Status()
		m["status_code"] = r.StatusCode()
		result[i] = m
		if err != nil {
			log.Printf("Error applying policy (%s:%s): %v\n",
				pol.ID, pol.Description, err)
			continue
		}
		if r.StatusCode() != http.StatusOK {
			log.Printf("Error applying policy (%s:%s): %s\n",
				pol.ID, pol.Description, r.Status())
			continue
		}
		reqPolicies.AppliedSuccessfully[i] = true
	}

	if isJSON {
		for i := range reqPolicies.SecurityPolicies {
			var h common.HttpError
			dc := &ms.DecoderConfig{TagName: "json", Result: &h}
			decoder, err := ms.NewDecoder(dc)
			if err != nil {
				continue
			}
			err = decoder.Decode(result[i])
			if err != nil {
				continue
			}
			status, _ := json.MarshalIndent(h, "", "\t")
			fmt.Println(string(status))
		}
	} else {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 0, '\t', 0)
		fmt.Println("New Policies Processed:")
		fmt.Fprintln(w, "Id\t",
			"Direction\t",
			"Successful Applied?\t",
		)
		for i, p := range reqPolicies.SecurityPolicies {
			fmt.Fprintf(w, "%s \t %s \t %t \n", p.ID,
				p.Direction, reqPolicies.AppliedSuccessfully[i])
		}
		w.Flush()
	}

	return nil
}

// policyRemove removes policy using the policy name provided
// as argument through args. It returns error if policy is not
// found, or returns a list of policy ID's if multiple policies
// with same name are found.
func policyRemove(cmd *cli.Command, args []string) error {

	if len(args) != 1 {
		return fmt.Errorf("Policy remove takes exactly one argument i.e policy id.")
	}

	var policy api.Policy
	policy.ID = args[0]

	rootURL := config.GetString("RootURL")
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetBody(policy).Delete(rootURL + "/policies")
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		JSONFormat(resp.Body(), os.Stdout)
	} else {
		if resp.StatusCode() == http.StatusOK {
			fmt.Printf("Policy (ID: %s) deleted successfully.\n", policy.ID)
		} else {
			fmt.Printf("Error deleting policy (ID: %s): %s\n",
				policy.ID, resp.Status())
		}
	}

	return nil
}

// policyList lists policies in tabular or json format.
func policyList(cmd *cli.Command, args []string) error {
	if len(args) > 0 {
		return util.UsageError(cmd,
			"Policy listing takes no arguments.")
	}
	return policyListShow(true, nil)
}

// policyShow displays details about a specific policy
// in tabular or json format.
func policyShow(cmd *cli.Command, args []string) error {
	return policyListShow(false, args)
}

// policyListShow lists/shows policies in tabular or json format.
func policyListShow(listOnly bool, args []string) error {
	specificPolicies := false
	if len(args) > 0 {
		specificPolicies = true
	}

	if !listOnly && !specificPolicies {
		return fmt.Errorf("Policy show takes at-least one argument i.e policy id/s.")
	}

	rootURL := config.GetString("RootURL")
	resp, err := resty.R().Get(rootURL + "/policies")
	if err != nil {
		return err
	}

	var allPolicies []api.Policy
	err = json.Unmarshal(resp.Body(), &allPolicies)
	if err != nil {
		return err
	}

	var policies []api.Policy
	if listOnly {
		policies = allPolicies
	} else {
		if specificPolicies {
			for _, a := range args {
				for _, p := range allPolicies {
					if a == p.ID {
						policies = append(policies, p)
					}
				}
			}
		}
	}

	if config.GetString("Format") == "json" {
		body, _ := json.MarshalIndent(policies, "", "\t")
		fmt.Println(string(body))
	} else {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 0, '\t', 0)
		if listOnly {
			fmt.Println("Policy List")
			fmt.Fprintln(w, "Policy Id\t",
				"Direction\t",
				"Applied to\t",
				"No of Peers\t",
				"No of Rules\t",
				"Description\t",
			)
		} else {
			fmt.Println("Policy Details")
		}
		for _, p := range policies {
			if listOnly {
				noOfPeers := 0
				noOfRules := 0
				for i := range p.Ingress {
					noOfPeers += len(p.Ingress[i].Peers)
					noOfRules += len(p.Ingress[i].Rules)
				}

				fmt.Fprintln(w, p.ID, "\t",
					p.Direction, "\t",
					len(p.AppliedTo), "\t",
					noOfPeers, "\t",
					noOfRules, "\t",
					p.Description, "\t",
				)
			} else {
				fmt.Fprint(w,
					"Policy Id:\t", p.ID, "\n",
					"Direction:\t", p.Direction, "\n",
					"Description:\t", p.Description, "\n",
				)
				if len(p.AppliedTo) > 0 {
					fmt.Fprintln(w, "Applied To:")
					for _, ato := range p.AppliedTo {
						fmt.Fprintln(w,
							"\tPeer:\t", ato.Peer, "\n",
							"\tCidr:\t", ato.Cidr, "\n",
							"\tDestination:\t", ato.Dest, "\n",
							"\tTenantID:\t", ato.TenantID, "\n",
							"\tSegmentID:\t", ato.SegmentID,
						)
					}
				}
				if len(p.Ingress) > 0 {
					for _, ingress := range p.Ingress {
						if len(ingress.Peers) > 0 {
							fmt.Fprintln(w, "Peers:")
							for _, peer := range ingress.Peers {
								fmt.Fprintln(w,
									"\tPeer:\t", peer.Peer, "\n",
									"\tCidr:\t", peer.Cidr, "\n",
									"\tDestination:\t", peer.Dest, "\n",
									"\tTenantID:\t", peer.TenantID, "\n",
									"\tSegmentID:\t", peer.SegmentID,
								)
							}
						}
						if len(ingress.Rules) > 0 {
							fmt.Fprintln(w, "Rules:")
							for _, rule := range ingress.Rules {
								fmt.Fprintln(w,
									"\tProtocol:\t", rule.Protocol, "\n",
									"\tIsStateful:\t", rule.IsStateful, "\n",
									"\tPorts:\t", rule.Ports, "\n",
									"\tPortRanges:\t", rule.PortRanges, "\n",
									"\tIcmpType:\t", rule.IcmpType, "\n",
									"\tIcmpCode:\t", rule.IcmpCode,
								)
							}
						}
					}
				}
				fmt.Fprintln(w, "")
			}
		}
		w.Flush()
	}

	return nil
}
