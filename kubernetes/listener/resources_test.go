package kubernetes

import (
	"github.com/romana/core/common"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.5/pkg/api/v1"
	"testing"
)

func TestSyncNetworkPolicies(t *testing.T) {

	var allRomanaPolicies []common.Policy
	var kubePolicies []v1beta1.NetworkPolicy
	getAllPoliciesFunc = func(none *common.RestClient) ([]common.Policy, error) {
		return allRomanaPolicies, nil
	}

	allRomanaPolicies = []common.Policy{
		common.Policy{
			Name: "donotdelete",
		},
		common.Policy{
			Name: "kube.default.deleteme",
		},
		common.Policy{
			Name: "kube.default.newPolicy1",
		},
	}

	kubePolicies = []v1beta1.NetworkPolicy{
		v1beta1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{Name: "newPolicy1"},
		},
		v1beta1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{Name: "newPolicy2"},
		},
	}

	l := &kubeListener{}
	newKubePolicies, oldRomanaPolicies, _ := l.syncNetworkPolicies(kubePolicies)

	if len(oldRomanaPolicies) != 1 || len(newKubePolicies) != 1 {
		t.Errorf("Received %d newKubePolicies (expect 1) and %d oldRomanaPolicies (expect 1)", len(newKubePolicies), len(oldRomanaPolicies))
	}

	if oldRomanaPolicies[0].Name != "kube.default.deleteme" {
		t.Errorf("Wrong romana policy scheduled for deletion %s - expected kube.default.deleteme", oldRomanaPolicies[0])
	}

	newKubePolicy, ok := newKubePolicies[0].Object.(v1beta1.NetworkPolicy)
	if !ok {
		t.Error("Failed to cast v1beta1.NetworkPolicy")
	}

	if newKubePolicy.ObjectMeta.Name != "newPolicy2" {
		t.Errorf("Wrong kube policy scheduled for creation %s - expected newPolicy2", newKubePolicy.ObjectMeta.Name)
	}
}
