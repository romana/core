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

package listener

import (
	"sync"
	"testing"

	"github.com/romana/core/common"
	"github.com/romana/core/tenant"

	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.5/pkg/util/intstr"
)

func TestTranslateTarget(t *testing.T) {
	tg := TranslateGroup{
		kubePolicy: &v1beta1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "default",
			},
		},
		romanaPolicy: &common.Policy{
			Name: "TestPolicy",
		},
	}

	translator := Translator{
		tenantsCache: []TenantCacheEntry{
			TenantCacheEntry{
				Tenant: tenant.Tenant{
					Name: "default",
					ID:   3,
				},
				Segments: []tenant.Segment{
					tenant.Segment{
						Name: "TestSegment",
						ID:   2,
					},
				},
			},
		},
		cacheMu:          &sync.Mutex{},
		segmentLabelName: "role",
	}

	testCases := []struct {
		PodSelector  v1beta1.LabelSelector
		RomanaPolicy common.Policy
		expected     func(*common.Policy) bool
	}{
		{
			PodSelector: v1beta1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithoutTargetSegment",
			},
			expected: func(p *common.Policy) bool {
				return p.AppliedTo[0].TenantID == 3
			},
		}, {
			PodSelector: v1beta1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "TestSegment",
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithSegment",
			},
			expected: func(p *common.Policy) bool {
				return p.AppliedTo[0].SegmentID == 2
			},
		},
	}

	for _, testCase := range testCases {
		tg.kubePolicy.Spec.PodSelector = testCase.PodSelector
		tg.romanaPolicy = &testCase.RomanaPolicy
		err := tg.translateTarget(&translator)
		if err != nil {
			t.Errorf("%s", err)
		}

		if !testCase.expected(tg.romanaPolicy) {
			t.Errorf("Failed to translate romana policy %s", tg.romanaPolicy.Name)
		}
	}
}

func TestMakeNextIngressPeer(t *testing.T) {
	tg := TranslateGroup{
		kubePolicy: &v1beta1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "default",
			},
			Spec: v1beta1.NetworkPolicySpec{
				Ingress: []v1beta1.NetworkPolicyIngressRule{
					v1beta1.NetworkPolicyIngressRule{},
				},
			},
		},
		romanaPolicy: &common.Policy{
			Name: "TestPolicy",
		},
		ingressIndex: 0,
	}

	translator := Translator{
		tenantsCache: []TenantCacheEntry{
			TenantCacheEntry{
				Tenant: tenant.Tenant{
					Name: "default",
					ID:   3,
				},
				Segments: []tenant.Segment{
					tenant.Segment{
						Name: "TestSegment",
						ID:   2,
					},
					tenant.Segment{
						Name: "AnotherTestSegment",
						ID:   3,
					},
				},
			},
			TenantCacheEntry{
				Tenant: tenant.Tenant{
					Name: "source-tenant",
					ID:   4,
				},
			},
		},
		cacheMu:          &sync.Mutex{},
		segmentLabelName: "role",
		tenantLabelName:  "tenantName",
	}

	testCases := []struct {
		From         []v1beta1.NetworkPolicyPeer
		RomanaPolicy common.Policy
		expected     func(*common.Policy) bool
	}{
		{
			From: []v1beta1.NetworkPolicyPeer{
				v1beta1.NetworkPolicyPeer{
					PodSelector: &v1beta1.LabelSelector{},
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithoutSegment",
				Ingress: []common.RomanaIngress{
					common.RomanaIngress{},
				},
			},
			expected: func(p *common.Policy) bool {
				return p.Ingress[0].Peers[0].TenantID == 3
			},
		}, {
			From: []v1beta1.NetworkPolicyPeer{
				v1beta1.NetworkPolicyPeer{
					NamespaceSelector: &v1beta1.LabelSelector{
						MatchLabels: map[string]string{
							"tenantName": "source-tenant",
						},
					},
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithoutSegment",
				Ingress: []common.RomanaIngress{
					common.RomanaIngress{},
				},
			},
			expected: func(p *common.Policy) bool {
				return p.Ingress[0].Peers[0].TenantID == 4
			},
		}, {
			From: []v1beta1.NetworkPolicyPeer{
				v1beta1.NetworkPolicyPeer{
					PodSelector: &v1beta1.LabelSelector{
						MatchLabels: map[string]string{
							"role": "TestSegment",
						},
					},
				},
				v1beta1.NetworkPolicyPeer{
					PodSelector: &v1beta1.LabelSelector{
						MatchLabels: map[string]string{
							"role": "AnotherTestSegment",
						},
					},
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithSegments",
				Ingress: []common.RomanaIngress{
					common.RomanaIngress{},
				},
			},
			expected: func(p *common.Policy) bool {
				return p.Ingress[0].Peers[0].TenantID == 3 && p.Ingress[0].Peers[0].SegmentID == 2 && p.Ingress[0].Peers[1].TenantID == 3 && p.Ingress[0].Peers[1].SegmentID == 3
			},
		},
	}

	for _, testCase := range testCases {
		tg.kubePolicy.Spec.Ingress[tg.ingressIndex].From = testCase.From
		tg.romanaPolicy = &testCase.RomanaPolicy
		err := tg.makeNextIngressPeer(&translator)
		if err != nil {
			t.Errorf("%s", err)
		}

		if !testCase.expected(tg.romanaPolicy) {
			t.Errorf("Failed to translate romana policy %s", tg.romanaPolicy.Name)
		}
	}
}

func TestMakeNextRule(t *testing.T) {
	tg := TranslateGroup{
		kubePolicy: &v1beta1.NetworkPolicy{
			Spec: v1beta1.NetworkPolicySpec{
				Ingress: []v1beta1.NetworkPolicyIngressRule{
					v1beta1.NetworkPolicyIngressRule{},
				},
			},
		},
		romanaPolicy: &common.Policy{
			Name: "TestPolicy",
		},
		ingressIndex: 0,
	}

	translator := Translator{
		cacheMu:          &sync.Mutex{},
		segmentLabelName: "role",
	}

	var portTCP v1.Protocol = "TCP"
	var portUDP v1.Protocol = "UDP"
	var port53 intstr.IntOrString = intstr.FromInt(53)
	var port80 intstr.IntOrString = intstr.FromInt(80)

	testCases := []struct {
		ToPorts      []v1beta1.NetworkPolicyPort
		RomanaPolicy common.Policy
		expected     func(*common.Policy) bool
	}{
		{
			ToPorts: []v1beta1.NetworkPolicyPort{
				v1beta1.NetworkPolicyPort{
					Port:     &port80,
					Protocol: &portTCP,
				},
				v1beta1.NetworkPolicyPort{
					Port:     &port53,
					Protocol: &portUDP,
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithPorts",
				Ingress: []common.RomanaIngress{
					common.RomanaIngress{},
				},
			},
			expected: func(p *common.Policy) bool {
				return p.Ingress[0].Rules[0].Ports[0] == 80 && p.Ingress[0].Rules[0].Protocol == "tcp" && p.Ingress[0].Rules[1].Ports[0] == 53 && p.Ingress[0].Rules[1].Protocol == "udp"
			},
		},
	}

	for _, testCase := range testCases {
		tg.kubePolicy.Spec.Ingress[tg.ingressIndex].Ports = testCase.ToPorts
		tg.romanaPolicy = &testCase.RomanaPolicy
		err := tg.makeNextRule(&translator)
		if err != nil {
			t.Errorf("%s", err)
		}

		if !testCase.expected(tg.romanaPolicy) {
			t.Errorf("Failed to translate romana policy %s", tg.romanaPolicy.Name)
		}
	}
}
