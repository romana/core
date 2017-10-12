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
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/romana/core/common/api"

	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/util/intstr"
)

var tdir = "testdata"

func TestTranslatePolicy(t *testing.T) {
	files, err := ioutil.ReadDir(tdir)
	if err != nil {
		t.Skip("Folder with test data not found")
	}

	loadKubePolicy := func(file string) (*v1beta1.NetworkPolicy, error) {
		data, err := ioutil.ReadFile(filepath.Join(tdir, file))
		if err != nil {
			return nil, err
		}

		var policy v1beta1.NetworkPolicy

		err = json.Unmarshal(data, &policy)

		if err != nil {
			return nil, err
		}

		return &policy, nil
	}

	loadRomanaPolicy := func(file string) (*api.Policy, error) {
		data, err := ioutil.ReadFile(filepath.Join(tdir, file))
		if err != nil {
			return nil, err
		}

		var policy api.Policy

		err = json.Unmarshal(data, &policy)

		if err != nil {
			return nil, err
		}

		return &policy, nil
	}

	translator := Translator{
		cacheMu:          &sync.Mutex{},
		segmentLabelName: "romana.io/segment",
	}

	policyToList := func(p ...v1beta1.NetworkPolicy) []v1beta1.NetworkPolicy { return p }

	// Loads file as kube policy and translates it to Romana policy,
	// then loads reference Romana policy from .json file and compares.
	test := func(file string, t *testing.T) func(*testing.T) {
		return func(t *testing.T) {
			policy, err := loadKubePolicy(file)
			if err != nil {
				t.Fatalf("failed to read policy %s, err=%s", file, err)
			}

			romanaPolicy, _, err := translator.Kube2RomanaBulk(policyToList(*policy))
			if err != nil {
				t.Fatalf("failed to convert k8s policy to romana policy, err=%s", err)
			}

			referencePolicyName := strings.Replace(file, ".kube", ".json", -1)
			referencePolicy, err := loadRomanaPolicy(referencePolicyName)
			if err != nil {
				t.Fatalf("failed to load reference policy %s, err=%s", file, err)
			}

			if len(romanaPolicy) > 0 && romanaPolicy[0].String() == referencePolicy.String() {
				t.Fatalf("policy\n%s\ndoesn't match reference policy\n%s", romanaPolicy, referencePolicy)
			}

		}
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".kube") {
			t.Run(file.Name(), test(file.Name(), t))
		}
	}
}

func TestTranslateTarget(t *testing.T) {
	tg := TranslateGroup{
		kubePolicy: &v1beta1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "default",
			},
		},
		romanaPolicy: &api.Policy{
			ID: "TestPolicy",
		},
	}

	translator := Translator{
		cacheMu:          &sync.Mutex{},
		segmentLabelName: "role",
	}

	testCases := []struct {
		PodSelector  unversioned.LabelSelector
		RomanaPolicy api.Policy
		expected     func(*api.Policy) bool
	}{
		{
			PodSelector: unversioned.LabelSelector{
				MatchLabels: map[string]string{},
			},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithoutTargetSegment",
			},
			expected: func(p *api.Policy) bool {
				return p.AppliedTo[0].TenantID == "default"
			},
		},
		{
			PodSelector: unversioned.LabelSelector{
				MatchLabels: map[string]string{
					"unrelated_label": "banana",
				},
			},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithoutTargetSegment2",
			},
			expected: func(p *api.Policy) bool {
				return p.AppliedTo[0].TenantID == "default"
			},
		}, {
			PodSelector: unversioned.LabelSelector{
				MatchLabels: map[string]string{
					"role": "TestSegment",
				},
			},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithSegment",
			},
			expected: func(p *api.Policy) bool {
				return p.AppliedTo[0].SegmentID == "TestSegment"
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
			t.Errorf("Failed to translate romana policy %s", tg.romanaPolicy.ID)
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
		romanaPolicy: &api.Policy{
			ID: "TestPolicy",
		},
		ingressIndex: 0,
	}

	translator := Translator{
		cacheMu:          &sync.Mutex{},
		segmentLabelName: "role",
		tenantLabelName:  "tenantName",
	}

	testCases := []struct {
		From         []v1beta1.NetworkPolicyPeer
		RomanaPolicy api.Policy
		expected     func(*api.Policy) bool
	}{
		{
			From: []v1beta1.NetworkPolicyPeer{
				v1beta1.NetworkPolicyPeer{
					PodSelector: &unversioned.LabelSelector{},
				},
			},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithoutSegment",
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{},
				},
			},
			expected: func(p *api.Policy) bool {
				return p.Ingress[0].Peers[0].TenantID == "default"
			},
		}, {
			From: []v1beta1.NetworkPolicyPeer{
				v1beta1.NetworkPolicyPeer{
					NamespaceSelector: &unversioned.LabelSelector{
						MatchLabels: map[string]string{
							"tenantName": "source-tenant",
						},
					},
				},
			},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithoutSegment",
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{},
				},
			},
			expected: func(p *api.Policy) bool {
				return p.Ingress[0].Peers[0].TenantID == "source-tenant"
			},
		}, {
			From: []v1beta1.NetworkPolicyPeer{
				v1beta1.NetworkPolicyPeer{
					PodSelector: &unversioned.LabelSelector{
						MatchLabels: map[string]string{
							"role": "TestSegment",
						},
					},
				},
				v1beta1.NetworkPolicyPeer{
					PodSelector: &unversioned.LabelSelector{
						MatchLabels: map[string]string{
							"role": "AnotherTestSegment",
						},
					},
				},
			},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithSegments",
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{},
				},
			},
			expected: func(p *api.Policy) bool {
				return p.Ingress[0].Peers[0].TenantID == "default" && p.Ingress[0].Peers[0].SegmentID == "TestSegment" && p.Ingress[0].Peers[1].TenantID == "default" && p.Ingress[0].Peers[1].SegmentID == "AnotherTestSegment"
			},
		}, {
			From: []v1beta1.NetworkPolicyPeer{},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyEmtyIngress",
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{},
				},
			},
			expected: func(p *api.Policy) bool {
				return p.Ingress[0].Peers[0].Peer == "any"
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
			t.Errorf("Failed to translate romana policy %s", tg.romanaPolicy.ID)
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
		romanaPolicy: &api.Policy{
			ID: "TestPolicy",
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
		RomanaPolicy api.Policy
		expected     func(*api.Policy) bool
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
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithPorts",
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{},
				},
			},
			expected: func(p *api.Policy) bool {
				return p.Ingress[0].Rules[0].Ports[0] == 80 && p.Ingress[0].Rules[0].Protocol == "tcp" && p.Ingress[0].Rules[1].Ports[0] == 53 && p.Ingress[0].Rules[1].Protocol == "udp"
			},
		}, {
			ToPorts: []v1beta1.NetworkPolicyPort{},
			RomanaPolicy: api.Policy{
				ID: "TestPolicyWithPorts",
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{},
				},
			},
			expected: func(p *api.Policy) bool {
				return p.Ingress[0].Rules[0].Protocol == api.Wildcard
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
			t.Errorf("Failed to translate romana policy %s", tg.romanaPolicy.ID)
		}
	}
}
