// Copyright (c) 2016 Pani Networks
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

package enforcer

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/romana/rlog"
)

var (
	ErrMakeSets = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "err_make_sets",
			Help: "Number of errors attempting to build ipset Sets.",
		},
	)
	ErrApplySets = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "err_apply_sets",
			Help: "Number of errors attempting to apply ipset Sets.",
		},
	)
	ErrValidateIptables = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "err_validate_iptables",
			Help: "Number of errors when validating iptables.",
		},
	)
	ErrApplyIptables = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "err_apply_iptables",
			Help: "Number of errors attempting to apply iptables.",
		},
	)
	NumPolicyUpdates = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "num_policy_updates",
			Help: "Number of policy updates processed.",
		},
	)
	NumBlockUpdates = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "num_block_updates",
			Help: "Number of block updates processed.",
		},
	)
	NumEnforcerTick = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "num_enforcer_ticks",
			Help: "Number of enforcer ticks since start.",
		},
	)
	NumManagedSets = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "num_managed_sets",
			Help: "Number ipset sets managed by Romana policy.",
		},
	)
	NumPolicyRules = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "num_policy_rules",
			Help: "Number of Romana policy rules applied to the host.",
		},
	)
)

func init() {
	for _, counter := range []prometheus.Counter{
		ErrMakeSets,
		ErrApplySets,
		ErrValidateIptables,
		ErrApplyIptables,
		NumPolicyUpdates,
		NumBlockUpdates,
		NumEnforcerTick,
		NumManagedSets,
		NumPolicyRules,
	} {
		err := prometheus.Register(counter)
		if err != nil {
			rlog.Error("Failed to register metric", err)
		}
	}
}
