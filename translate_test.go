package kubernetes

import (
//	"encoding/json"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"sync"
	//	"bytes"
	"testing"
)

// const A = `{ "Spec" :{ "podSelector" : { "MatchLabels" : { "Key1" : "Val1", "Key2" : "Val2" } } } }`

func TestTranslateTarget(t *testing.T) {
	tg := TranslateGroup{
		kubePolicy: &KubeObject{
			Metadata: Metadata{
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
						ID: 2,
					},
				},
			},
		},
		cacheMu: &sync.Mutex{},
		segmentLabelName: "role",
	}

	testCases := []struct {
		PodSelector  PodSelector
		RomanaPolicy common.Policy
		expected     func(*common.Policy) bool
	}{
		{
			PodSelector: PodSelector{
				MatchLabels: map[string]string{},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithoutTargetSegment",
			},
			expected: func(p *common.Policy) bool {
				return p.AppliedTo[0].TenantID == 3
			},
		},{
			PodSelector: PodSelector{
				MatchLabels: map[string]string{
					"role" : "TestSegment",
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

func TestMakeNextSource(t *testing.T) {
	tg := TranslateGroup{
		kubePolicy: &KubeObject{
			Metadata: Metadata{
				Namespace: "default",
			},
			Spec: Spec{
				Ingress: []Ingress{
					Ingress{},
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
						ID: 2,
					},
					tenant.Segment{
						Name: "AnotherTestSegment",
						ID: 3,
					},
				},
			},
		},
		cacheMu: &sync.Mutex{},
		segmentLabelName: "role",
	}

	testCases := []struct {
		From	[]FromEntry
		RomanaPolicy common.Policy
		expected     func(*common.Policy) bool
	}{
		{
			From: []FromEntry{
				FromEntry{
					Pods: PodSelector{
						MatchLabels: map[string]string{},
					},
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithoutSegment",
			},
			expected: func(p *common.Policy) bool {
				return p.Peers[0].TenantID == 3
			},
		},{
			From: []FromEntry{
				FromEntry{
					Pods: PodSelector{
						MatchLabels: map[string]string{
							"role" : "TestSegment",
						},
					},
				},
				FromEntry{
					Pods: PodSelector{
						MatchLabels: map[string]string{
							"role" : "AnotherTestSegment",
						},
					},
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithSegments",
			},
			expected: func(p *common.Policy) bool {
				return p.Peers[0].TenantID == 3 && p.Peers[0].SegmentID == 2 && p.Peers[1].TenantID == 3 && p.Peers[1].SegmentID == 3
			},
		},
	}

	for _, testCase := range testCases {
		tg.kubePolicy.Spec.Ingress[tg.ingressIndex].From = testCase.From
		tg.romanaPolicy = &testCase.RomanaPolicy
		err := tg.makeNextSource(&translator)
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
		kubePolicy: &KubeObject{
			Spec: Spec{
				Ingress: []Ingress{
					Ingress{},
				},
			},
		},
		romanaPolicy: &common.Policy{
			Name: "TestPolicy",
		},
		ingressIndex: 0,
	}

	translator := Translator{
		cacheMu: &sync.Mutex{},
		segmentLabelName: "role",
	}

	testCases := []struct {
		ToPorts	[]ToPort
		RomanaPolicy common.Policy
		expected     func(*common.Policy) bool
	}{
		{
			ToPorts: []ToPort{
				ToPort{
					Port: 80,
					Protocol: "TCP",
				},
				ToPort{
					Port: 53,
					Protocol: "UDP",
				},

			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithPorts",
			},
			expected: func(p *common.Policy) bool {
				return p.Rules[0].Ports[0] == 80 && p.Rules[0].Protocol == "tcp" && p.Rules[1].Ports[0] == 53 && p.Rules[1].Protocol == "udp"
			},
		},
	}

	for _, testCase := range testCases {
		tg.kubePolicy.Spec.Ingress[tg.ingressIndex].ToPorts = testCase.ToPorts
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
