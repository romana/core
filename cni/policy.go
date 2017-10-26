// Copyright (c) 2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package cni

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/romana/core/agent/iptsave"
	"github.com/romana/rlog"
)

func enablePodPolicy(ifaceName string) error {
	return manageDivertRules(MakeDivertRules(ifaceName, iptsave.RenderAppendRule))
}

func disablePodPolicy(ifaceName string) error {
	return manageDivertRules(MakeDivertRules(ifaceName, iptsave.RenderDeleteRule))
}

func manageDivertRules(divertRules []*iptsave.IPchain) error {
	IptablesBin, err := exec.LookPath("iptables")
	if err != nil {
		return err
	}

	var rules string
	for _, chain := range divertRules {
		rules += chain.RenderFooter()
	}

	makeArgs := func(a []string, b ...string) []string {
		var result []string
		result = append(b, a...)
		return result
	}

	for _, rule := range strings.Split(rules, "\n") {
		if rule == "" {
			continue
		}
		rlog.Debugf("EXEC %s", makeArgs(strings.Split(rule, " ")), IptablesBin, "-t", "filter")
		data, err := exec.Command(IptablesBin, makeArgs(strings.Split(rule, " "), "-t", "filter")...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s, err=%s", data, err)
		}
	}

	return nil
}
