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
	"io/ioutil"
	"log"
	"os"
	"text/tabwriter"

	"github.com/romana/core/common"
	"github.com/romana/core/romana/util"

	ms "github.com/mitchellh/mapstructure"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

const (
	MAX_UINT64 = ^uint64(0)
)

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
	policyRemoveCmd.Flags().Uint64VarP(&policyID, "policyid", "i", MAX_UINT64, "Policy ID")
}

var policyAddCmd = &cli.Command{
	Use:          "add [policyFile]",
	Short:        "Add a new policy.",
	Long:         `Add a new policy.`,
	RunE:         policyAdd,
	SilenceUsage: true,
}

var policyRemoveCmd = &cli.Command{
	Use:          "remove [policyName]",
	Short:        "Remove a specific policy.",
	Long:         `Remove a specific policy.`,
	RunE:         policyRemove,
	SilenceUsage: true,
}

var policyListCmd = &cli.Command{
	Use:          "list",
	Short:        "List policy for a specific tenant.",
	Long:         `List policy for a specific tenant.`,
	RunE:         policyList,
	SilenceUsage: true,
}

// policyAdd adds kubernetes policy for a specific tenant
// using the policyFile provided.
func policyAdd(cmd *cli.Command, args []string) error {
	var buf []byte
	var policyFile string
	var err error
	isFile := true
	isJson := config.GetString("Format") == "json"

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

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
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
		err = json.Unmarshal(pBuf, &reqPolicies)
		if err != nil || len(reqPolicies.SecurityPolicies) == 0 {
			reqPolicies.SecurityPolicies = make([]common.Policy, 1)
			err = json.Unmarshal(pBuf, &reqPolicies.SecurityPolicies[0])
			if err != nil {
				return err
			}
		}
	} else {
		err = json.Unmarshal(buf, &reqPolicies)
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
			log.Printf("Error in client.Post(): %v", err)
			continue
		}
		reqPolicies.AppliedSuccessfully[i] = true
	}

	if isJson {
		for i, _ := range reqPolicies.SecurityPolicies {
			// check if any of policy markers are present in the map.
			_, exOk := result[i]["external_id"]
			_, idOk := result[i]["id"]
			_, nmOk := result[i]["name"]
			if exOk || idOk || nmOk {
				var p common.Policy
				err := ms.Decode(result[i], &p)
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
				err := ms.Decode(result[i], &p)
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

	return nil
}

// getPolicyIDs returns a slice of Policy IDs for a given
// policy name, since multiple policies with same name
// can exists.
func getPolicyID(policyName string) (uint64, error) {
	rootURL := config.GetString("RootURL")

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
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

// policyRemove removes policy using the policyName provided,
// it return error if policy not found, or returns a list of
// policy ID's if multiple policies with same name are found.
func policyRemove(cmd *cli.Command, args []string) error {
	var policyName string
	policyIDPresent := false

	if policyID != MAX_UINT64 && len(args) == 0 {
		policyIDPresent = true
	} else if policyID == MAX_UINT64 && len(args) == 1 {
		policyName = args[0]
	} else {
		return util.UsageError(cmd,
			"POLICY_NAME (or --policyid <id> ) should be provided.")
	}

	rootURL := config.GetString("RootURL")

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
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

// policyList lists policies for a specific tenant.
func policyList(cmd *cli.Command, args []string) error {
	rootURL := config.GetString("RootURL")

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
	if err != nil {
		return err
	}

	policyURL, err := client.GetServiceUrl("policy")
	if err != nil {
		return err
	}

	policies := []common.Policy{}
	err = client.Get(policyURL+"/policies", &policies)
	if err != nil {
		return err
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
		fmt.Println("Policy List")
		fmt.Fprintln(w, "Id\t",
			"Policy\t",
			"Direction\t",
			"Tenant ID\t",
			"Segment ID\t",
			"ExternalID\t",
			"Description\t",
		)
		for _, p := range policies {
			fmt.Fprintln(w, p.ID, "\t",
				p.Name, "\t",
				p.Direction, "\t",
				p.AppliedTo[0].TenantID, "\t",
				p.AppliedTo[0].SegmentID, "\t",
				p.ExternalID, "\t",
				p.Description, "\t",
			)
		}
		w.Flush()
	}

	return nil
}
