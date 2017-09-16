package cni

import (
	"os/exec"

	"github.com/romana/core/agent/enforcer"
	utilexec "github.com/romana/core/agent/exec"
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
	var err error
	if enforcer.IptablesSaveBin, err = exec.LookPath("iptables-save"); err != nil {
		return err
	}

	if enforcer.IptablesRestoreBin, err = exec.LookPath("iptables-restore"); err != nil {
		return err
	}

	iptables := iptsave.IPtables{
		Tables: []*iptsave.IPtable{
			&iptsave.IPtable{
				Name:   "filter",
				Chains: divertRules,
			},
		},
	}

	rlog.Debugf("About to install iptables rules %s", iptables.Render())

	return enforcer.ApplyIPtables(&iptables, new(utilexec.DefaultExecutor))
}
