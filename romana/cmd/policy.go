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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/romana/core/common"
	"github.com/romana/core/romana/util"

	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
)

const (
	MAX_UINT64 = ^uint64(0)
)

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
	Use:          "add [tenantName][policyFile]",
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
	Use:          "list [tenantName]",
	Short:        "List policy for a specific tenant.",
	Long:         `List policy for a specific tenant.`,
	RunE:         policyList,
	SilenceUsage: true,
}

// policyAdd adds kubernetes policy for a specific tenant
// using the policyFile provided.
func policyAdd(cmd *cli.Command, args []string) error {
	var buf *bytes.Reader
	var policyFile string

	if len(args) == 1 {
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			util.UsageError(cmd,
				"POLICY FILE name or piped input from 'STDIN' expected.")
			return fmt.Errorf("Cannot read 'STDIN': %s\n", err)
		}
		buf = bytes.NewReader(b)
	} else if len(args) != 2 {
		return util.UsageError(cmd,
			"TENANT and POLICY FILE name should be provided.")
	}

	tenantName := args[0]
	// Tenant check once adaptor add supports for it.
	/*
		if !adaptor.TenantExists(tnt) {
			return errors.New("Tenant doesn't exists: " + tnt)
		}
	*/

	// TODO: handle user and versioning info according to
	//       to policy service instead of encoding it in url.
	kubeURL := (config.GetString("BaseURL") +
		fmt.Sprintf(":8080/apis/romana.io/demo/v1") +
		fmt.Sprintf("/namespaces/%s/networkpolicys", tenantName))

	var req *http.Request
	var err error
	if len(args) == 2 {
		var f *os.File
		policyFile = args[1]

		f, err = os.Open(policyFile)
		if err != nil {
			return errors.New("Couldn't open Policy file: " + policyFile)
		}
		defer f.Close()

		req, err = http.NewRequest("POST", kubeURL, f)
	} else {
		req, err = http.NewRequest("POST", kubeURL, buf)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if config.GetString("Format") == "json" {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf(util.JSONIndent(string(body)))
	} else {
		if resp.StatusCode == http.StatusCreated {
			fmt.Printf("Policy (%s) for Tenant (%s) successfully created.\n",
				policyFile, tenantName)
		} else {
			return fmt.Errorf("Error creating Policy (%s) for Tenant (%s).",
				policyFile, tenantName)
		}
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
