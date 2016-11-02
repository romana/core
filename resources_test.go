package kubernetes

import (
	"bytes"
	"github.com/romana/core/common"
	"io"
	"testing"
)

func TestSyncNetworkPolicies(t *testing.T) {
	var allRomanaPolicies []common.Policy
	var kubePolicies []KubeObject
	var namespace string
	getAllPoliciesFunc = func(none *common.RestClient) ([]common.Policy, error) {
		return allRomanaPolicies, nil
	}

	namespace = "default"
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

	kubePolicies = []KubeObject{
		KubeObject{
			Metadata: Metadata{Name: "newPolicy1"},
		},
		KubeObject{
			Metadata: Metadata{Name: "newPolicy2"},
		},
	}

	l := &kubeListener{}
	newKubePolicies, oldRomanaPolicies, _ := l.syncNetworkPolicies(namespace, kubePolicies)

	if len(oldRomanaPolicies) != 1 || len(newKubePolicies) != 1 {
		t.Errorf("Received %d newKubePolicies (expect 1) and %d oldRomanaPolicies (expect 1)", len(newKubePolicies), len(oldRomanaPolicies))
	}

	if oldRomanaPolicies[0].Name != "kube.default.deleteme" {
		t.Errorf("Wrong romana policy scheduled for deletion %s - expected kube.default.deleteme", oldRomanaPolicies[0])
	}

	if newKubePolicies[0].Object.Metadata.Name != "newPolicy2" {
		t.Errorf("Wrong kube policy scheduled for creation %s - expected newPolicy2", newKubePolicies[0].Object.Metadata.Name)
	}
}

func TestWatchKubernetesResource(t *testing.T) {
	kubernetesResponse := []byte(`
	{
	  "kind": "NetworkPolicyList",
	  "metadata": { "resourceVersion": "1" },
	  "items": [
	    {
	      "metadata": {
		"name": "po9",
		"namespace": "http-tests",
		"uid": "5b4664e8-a0a5-11e6-825a-06d535b27c66"
	      }
	    }
	  ]
	}
	`)

	kubernetesStream := []byte(`
		{"type":"ADDED","object":{"kind":"NetworkPolicy","metadata":{"name":"po10","namespace":"http-tests"}}}
	`)

	httpGetFunc = func(url string) (io.Reader, error) {
		if url == "http://dummy:8080" {
			return bytes.NewReader(kubernetesResponse), nil
		} else if url == "http://dummy:8080?watch=true&resourceVersion=1" {
			return bytes.NewReader(kubernetesStream), nil
		} else {
			t.Errorf("Unexpected url called %s", url)
		}
		return bytes.NewReader([]byte(`{}`)), nil
	}

	done := make(chan Done)
	l := &kubeListener{}

	items, in, err := l.watchKubernetesResource("http://dummy:8080", done)
	if err != nil {
		t.Errorf("Unexpected error %s", err)
	}

	if len(items) != 1 {
		t.Errorf("Received %d items from kubernetes (expect 1)", len(items))
	}

	if items[0].Metadata.Name != "po9" {
		t.Errorf("Received policy %s from kubernetes (expect po9)", items[0].Metadata.Name)
	}

	e := <-in
	if e.Object.Metadata.Name != "po10" {
		t.Errorf("Received policy %s from kubernetes (expect p10)", e.Object.Metadata.Name)
	}
}
