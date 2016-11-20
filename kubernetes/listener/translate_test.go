package kubernetes

import (
	//	"encoding/json"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.5/pkg/util/intstr"
	"k8s.io/client-go/1.5/pkg/api/v1"
	"sync"
	//	"bytes"
	"testing"
)

// const A = `{ "Spec" :{ "podSelector" : { "MatchLabels" : { "Key1" : "Val1", "Key2" : "Val2" } } } }`

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
		},
		cacheMu:          &sync.Mutex{},
		segmentLabelName: "role",
	}

	testCases := []struct {
		From         []v1beta1.NetworkPolicyPeer
		RomanaPolicy common.Policy
		expected     func(*common.Policy) bool
	}{
		{
			From: []v1beta1.NetworkPolicyPeer{
				v1beta1.NetworkPolicyPeer{
					PodSelector: &v1beta1.LabelSelector{
					},
				},
			},
			RomanaPolicy: common.Policy{
				Name: "TestPolicyWithoutSegment",
			},
			expected: func(p *common.Policy) bool {
				return p.Peers[0].TenantID == 3
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
			},
			expected: func(p *common.Policy) bool {
				return p.Peers[0].TenantID == 3 && p.Peers[0].SegmentID == 2 && p.Peers[1].TenantID == 3 && p.Peers[1].SegmentID == 3
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
			},
			expected: func(p *common.Policy) bool {
				return p.Rules[0].Ports[0] == 80 && p.Rules[0].Protocol == "tcp" && p.Rules[1].Ports[0] == 53 && p.Rules[1].Protocol == "udp"
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
