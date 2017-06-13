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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"text/tabwriter"

	"github.com/romana/core/common"
	"github.com/romana/core/romana/util"
	log "github.com/romana/rlog"

	ms "github.com/mitchellh/mapstructure"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

// Policies structure is used to keep track of
// security policies and their status, as to if
// they were applied successfully or not.
type Policies struct {
	SecurityPolicies    []common.Policy
	AppliedSuccessfully []bool
}

var policyID uint64

// policyCmd represents the policy commands
var policyCmd = &cli.Command{
	Use:   "policy [add|remove|list]",
	Short: "Add, Remove or List a policy.",
	Long: `Add, Remove or List a policy.

For more information, please check http://romana.io
`,
}

func init() {
	policyCmd.AddCommand(policyAddCmd)
	policyCmd.AddCommand(policyRemoveCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyRemoveCmd.Flags().Uint64VarP(&policyID, "policyid", "i", 0, "Policy ID")
	policyShowCmd.Flags().Uint64VarP(&policyID, "policyid", "i", 0, "Policy ID")
}

var policyAddCmd = &cli.Command{
	Use:          "add [policyFile]",
	Short:        "Add a new policy.",
	Long:         `Add a new policy.`,
	RunE:         policyAdd,
	SilenceUsage: true,
}

var policyRemoveCmd = &cli.Command{
	Use:   "remove [policyName]",
	Short: "Remove a specific policy.",
	Long: `Remove a specific policy.

  --policyid <policy id>  # Remove policy using romana policy id.`,
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
	Use:   "show [Policy Name|Policy External ID]...",
	Short: "Show details about a specific policy using name or external id.",
	Long: `Show details about a specific policy using name or external id.

  --policyid <policy id>  # Show policy using romana policy id.`,
	RunE:         policyShow,
	SilenceUsage: true,
}

// policyAdd adds romana policy for a specific tenant
// using the policyFile provided or through input pipe.
// The features supported are:
//  * Policy addition through file with single policy in it
//  * Policy addition through file with multiple policies
//    in it supporting the SecurityPolicies construct as
//    shown in policy/policy.sample.json
//  * Both the above formats but taking input from standard
//    input (STDIN) instead of a file
//  * Tabular and json output for indication of policy
//    addition
func policyAdd(cmd *cli.Command, args []string) error {
	var buf []byte
	var policyFile string
	var err error
	somePoliciesFailed := false
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

	client, err := getRestClient()
	if err != nil {
		return err
	}

	policyURL, err := client.GetServiceUrl("policy")
	if err != nil {
		return err
	}

	reqPolicies := Policies{}
	if isFile {
		pBuf, err := ioutil.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("File error: %s\n", err)
		}
		err = json.Unmarshal(pBuf, &reqPolicies.SecurityPolicies)
		if err != nil || len(reqPolicies.SecurityPolicies) == 0 {
			reqPolicies.SecurityPolicies = make([]common.Policy, 1)
			err = json.Unmarshal(pBuf, &reqPolicies.SecurityPolicies[0])
			if err != nil {
				return err
			}
		}
	} else {
		err = json.Unmarshal(buf, &reqPolicies.SecurityPolicies)
		if err != nil || len(reqPolicies.SecurityPolicies) == 0 {
			reqPolicies.SecurityPolicies = make([]common.Policy, 1)
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
		err = client.Post(policyURL+"/policies", pol, &result[i])
		if err != nil {
			somePoliciesFailed = true
			log.Printf("Error in client.Post(): %v", err)
			continue
		}
		reqPolicies.AppliedSuccessfully[i] = true
	}

	if isJSON {
		for i := range reqPolicies.SecurityPolicies {
			// check if any of policy markers are present in the map.
			_, exOk := result[i]["external_id"]
			_, idOk := result[i]["id"]
			_, nmOk := result[i]["name"]
			if exOk || idOk || nmOk {
				var p common.Policy
				dc := &ms.DecoderConfig{TagName: "json", Result: &p}
				decoder, err := ms.NewDecoder(dc)
				if err != nil {
					continue
				}
				err = decoder.Decode(result[i])
				if err != nil {
					continue
				}
				body, err := json.MarshalIndent(p, "", "\t")
				if err != nil {
					continue
				}
				fmt.Println(string(body))
			} else {
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
		}
	} else {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 0, '\t', 0)
		fmt.Println("New Policies Processed:")
		fmt.Fprintln(w, "Id\t",
			"Policy Name\t",
			"Direction\t",
			"Successful Applied?\t",
		)
		for i, pol := range reqPolicies.SecurityPolicies {
			// check if any of policy markers are present in the map.
			_, exOk := result[i]["external_id"]
			_, idOk := result[i]["id"]
			_, nmOk := result[i]["name"]
			if exOk || idOk || nmOk {
				var p common.Policy
				dc := &ms.DecoderConfig{TagName: "json", Result: &p}
				decoder, err := ms.NewDecoder(dc)
				if err != nil {
					continue
				}
				err = decoder.Decode(result[i])
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "%d \t %s \t %s \t %t \n", p.ID,
					p.Name, p.Direction, reqPolicies.AppliedSuccessfully[i])
			} else {
				fmt.Fprintf(w, "%d \t %s \t %s \t %t \n", pol.ID,
					pol.Name, pol.Direction, false)
			}
		}
		w.Flush()
	}

	if somePoliciesFailed {
		if isJSON {
			os.Exit(255)
		} else {
			return errors.New("Some policies failed to apply.\n")
		}
	}

	return nil
}

// getPolicyID returns a Policy ID for a given policy
// name, since multiple policies with same name can
// exists, it returns the first one from them.
func getPolicyID(policyName string) (uint64, error) {
	client, err := getRestClient()
	if err != nil {
		return 0, err
	}

	policyURL, err := client.GetServiceUrl("policy")
	if err != nil {
		return 0, err
	}

	var policy common.Policy
	policyURL += fmt.Sprintf("/find/policies/%s", policyName)
	err = client.Get(policyURL, &policy)
	if err != nil {
		return 0, err
	}

	return policy.ID, nil
}

// policyRemove removes policy using the policy name provided
// as argument through args. It returns error if policy is not
// found, or returns a list of policy ID's if multiple policies
// with same name are found.
func policyRemove(cmd *cli.Command, args []string) error {
	var policyName string
	policyIDPresent := false

	if policyID != 0 && len(args) == 0 {
		policyIDPresent = true
	} else if policyID == 0 && len(args) == 1 {
		policyName = args[0]
	} else {
		return util.UsageError(cmd,
			"POLICY_NAME (or --policyid <id> ) should be provided.")
	}

	client, err := getRestClient()
	if err != nil {
		return err
	}

	policyURL, err := client.GetServiceUrl("policy")
	if err != nil {
		return err
	}

	policyResp := common.Policy{}

	if !policyIDPresent {
		var err error

		policyID, err = getPolicyID(policyName)
		if err != nil {
			return err
		}
	}

	policyURL += fmt.Sprintf("/policies/%d", policyID)
	err = client.Delete(policyURL, nil, &policyResp)
	if err != nil {
		return err
	}

	if config.GetString("Format") == "json" {
		body, err := json.MarshalIndent(policyResp, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(body))
	} else {
		if policyIDPresent {
			fmt.Printf("Policy (ID: %d) deleted successfully.\n", policyID)
		} else {
			fmt.Printf("Policy (%s) deleted successfully.\n", policyName)
		}
	}

	return nil
}

// policyList lists policies in tabular or json format.
func policyList(cmd *cli.Command, args []string) error {
	if len(args) > 0 || policyID != 0 {
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

	policyIDPresent := false
	if policyID != 0 {
		policyIDPresent = true
	}

	if !listOnly && !(specificPolicies || policyIDPresent) {
		return fmt.Errorf("Policy show takes at-least one argument or policy id.")
	}

	client, err := getRestClient()
	if err != nil {
		return err
	}

	policyURL, err := client.GetServiceUrl("policy")
	if err != nil {
		return err
	}

	allPolicies := []common.Policy{}
	err = client.Get(policyURL+"/policies", &allPolicies)
	if err != nil {
		return err
	}

	policies := []common.Policy{}
	if listOnly {
		policies = allPolicies
	} else {
		if specificPolicies && policyIDPresent {
			for _, p := range allPolicies {
				for _, a := range args {
					if a == p.Name || a == p.ExternalID || policyID == p.ID {
						policies = append(policies, p)
					}
				}
			}
		} else if !specificPolicies && policyIDPresent {
			for _, p := range allPolicies {
				if policyID == p.ID {
					policies = append(policies, p)
					break
				}
			}
		} else if specificPolicies && !policyIDPresent {
			for _, p := range allPolicies {
				for _, a := range args {
					if a == p.Name || a == p.ExternalID {
						policies = append(policies, p)
					}
				}
			}
		}
	}

	if config.GetString("Format") == "json" {
		body, err := json.MarshalIndent(policies, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(body))
	} else {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 0, '\t', 0)
		if listOnly {
			fmt.Println("Policy List")
			fmt.Fprintln(w, "Id\t",
				"Policy\t",
				"Direction\t",
				"ExternalID\t",
				"Description\t",
			)
		} else {
			fmt.Println("Policy Details")
		}
		for _, p := range policies {
			if listOnly {
				fmt.Fprintln(w, p.ID, "\t",
					p.Name, "\t",
					p.Direction, "\t",
					p.ExternalID, "\t",
					p.Description, "\t",
				)
			} else {
				fmt.Fprint(w,
					"Id:\t", p.ID, "\n",
					"Name:\t", p.Name, "\n",
					"External ID:\t", p.ExternalID, "\n",
					"Description:\t", p.Description, "\n",
				)
				if len(p.AppliedTo) > 0 {
					fmt.Fprintln(w, "Applied To:")
					for _, ato := range p.AppliedTo {
						fmt.Fprintln(w,
							"\tPeer:\t", ato.Peer, "\n",
							"\tCidr:\t", ato.Cidr, "\n",
							"\tTenantID:\t", ato.TenantID, "\n",
							"\tTenantName:\t", ato.TenantName, "\n",
							"\tSegmentID:\t", ato.SegmentID, "\n",
							"\tSegmentName:\t", ato.SegmentName,
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
									"\tTenantID:\t", peer.TenantID, "\n",
									"\tTenantName:\t", peer.TenantName, "\n",
									"\tSegmentID:\t", peer.SegmentID, "\n",
									"\tSegmentName:\t", peer.SegmentName,
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
