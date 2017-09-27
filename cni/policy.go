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
