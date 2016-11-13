package kubernetes

import (
//	"encoding/json"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"sync"
	//	"bytes"
//	"fmt"
	"testing"
)

const A = `{ "Spec" :{ "podSelector" : { "MatchLabels" : { "Key1" : "Val1", "Key2" : "Val2" } } } }`

func TestMakeTarget(t *testing.T) {
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
		err := tg.makeTarget(&translator)
		if err != nil {
			t.Errorf("%s", err)
		}

		if !testCase.expected(tg.romanaPolicy) {
			t.Errorf("Failed to translate romana policy %s", tg.romanaPolicy.Name)
		}
	}
}
