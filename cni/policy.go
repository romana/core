package cni

import (
	"github.com/romana/core/agent/enforcer"
	utilexec "github.com/romana/core/agent/exec"
	"github.com/romana/core/agent/iptsave"
)

func enablePodPolicy(ifaceName string) error {
	return manageDivertRules(MakeDivertRules(ifaceName, iptsave.RenderAppendRule))
}

func disablePodPolicy(ifaceName string) error {
	return manageDivertRules(MakeDivertRules(ifaceName, iptsave.RenderAppendRule))
}

func manageDivertRules(divertRules []*iptsave.IPchain) error {
	iptables := iptsave.IPtables{
		Tables: []*iptsave.IPtable{
			&iptsave.IPtable{
				Name:   "filter",
				Chains: divertRules,
			},
		},
	}

	return enforcer.ApplyIPtables(&iptables, new(utilexec.DefaultExecutor))
}
