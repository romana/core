// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package kubernetes implements kubernetes API specific
// helper functions.
package kubernetes

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"net/http"
	"strings"
	"sync"
)

type PolicyTranslator interface {
	Init(*common.RestClient, string)

	// Translates kubernetes policy into romana format.
	Kube2Romana(KubeObject) (common.Policy, error)

	// Translates number of kubernetes policies into romana format.
	// Returns a list of translated policies, list of original policies
	// that failed to translate and an error.
	Kube2RomanaBulk([]KubeObject) ([]common.Policy, []KubeObject, error)
}

type Translator struct {
	listener         *kubeListener
	restClient       *common.RestClient
	tenantsCache     []TenantCacheEntry
	cacheMu          sync.Mutex
	segmentLabelName string
}

// resolveTenantByName retrieves tenant information from romana.
func (l *Translator) resolveTenantByName(tenantName string) (*tenant.Tenant, error) {
	t := &tenant.Tenant{Name: tenantName}
	err := l.restClient.Find(t, common.FindLast)
	if err != nil {
		return t, err
	}
	return t, nil
}

// getOrAddSegment finds a segment (based on segment selector).
// If not found, it adds one.
func (l *Translator) getOrAddSegment(namespace string, kubeSegmentName string) (*tenant.Segment, error) {
	tenantCacheEntry := l.checkTenantInCache(namespace)
	if tenantCacheEntry == nil {
		return nil, TranslatorError{ErrorTenantNotIntCache, fmt.Errorf("Tenant not found in cache while resolving segment")}
	}

	segment := l.checkSegmentInCache(tenantCacheEntry, kubeSegmentName)
	if segment != nil {
		// Stop right here, we have what we
		// came for.
		return segment, nil

	}

	// This branch corresponds to a situation when
	// tenant found in the cache but segment isn't.
	// We will try to create a segment and update the cache.
	defer func() {
		err := l.updateCache()
		if err != nil {
			glog.Error("Failed to update cache in translator during getOrAddSegment().")
		}
	}()

	ten := tenantCacheEntry.Tenant
	seg := &tenant.Segment{}
	seg.Name = kubeSegmentName
	seg.TenantID = ten.ID
	err := l.restClient.Find(seg, common.FindExactlyOne)
	if err == nil {
		return seg, nil
	}

	switch err := err.(type) {
	case common.HttpError:
		if err.StatusCode == http.StatusNotFound {
			// Not found, so let's create a segment.
			segreq := tenant.Segment{Name: kubeSegmentName, TenantID: ten.ID}
			segURL, err2 := l.restClient.GetServiceUrl("tenant")
			if err2 != nil {
				return nil, err2
			}
			segURL = fmt.Sprintf("%s/tenants/%d/segments", segURL, ten.ID)
			err2 = l.restClient.Post(segURL, segreq, seg)
			if err2 == nil {
				// Successful creation.
				return seg, nil
			}
			// Creation of non-existing segment gave an error.
			switch err2 := err2.(type) {
			case common.HttpError:
				// Maybe someone else just created a segment between the original
				// lookup and now?
				if err2.StatusCode == http.StatusConflict {
					switch details := err2.Details.(type) {
					case tenant.Segment:
						// We expect the existing segment to be returned in the details field.
						return &details, nil
					default:
						// This is unexpected...
						return nil, err
					}
				}
				// Any other HTTP error other than a Conflict here - return it.
				return nil, err2
			default:
				// Any other error - return it
				return nil, err2
			}
		}
		// Any other HTTP error other than a Not found here - return it
		return nil, err
	default:
		// Any other error - return it
		return nil, err
	}
}

// translateNetworkPolicy translates a Kubernetes policy into
// Romana policy (see common.Policy) with the following rules:
// 1. Kubernetes Namespace corresponds to Romana Tenant
// 2. If Romana Tenant does not exist it is an error (a tenant should
//    automatically have been created when the namespace was added)
func (l *Translator) translateNetworkPolicy(kubePolicy *KubeObject) (common.Policy, error) {
	policyName := fmt.Sprintf("kube.%s.%s", kubePolicy.Metadata.Namespace, kubePolicy.Metadata.Name)
	romanaPolicy := &common.Policy{Direction: common.PolicyDirectionIngress, Name: policyName, ExternalID: kubePolicy.Metadata.Uid}
	ns := kubePolicy.Metadata.Namespace
	// TODO actually look up tenant K8S ID.
	tenantCacheEntry := l.checkTenantInCache(ns)
	if tenantCacheEntry == nil {
		return common.Policy{}, TranslatorError{ErrorTenantNotIntCache, nil}
	}

	t := tenantCacheEntry.Tenant
	glog.Infof("translateNetworkPolicy(): For namespace %s got %+v", ns, t)
	tenantID := t.ID
	tenantExternalID := t.ExternalID

	kubeSegmentID := kubePolicy.Spec.PodSelector.MatchLabels[l.segmentLabelName]
	if kubeSegmentID == "" {
		glog.Errorf("DEBUG Expected segment to be specified in podSelector part as %s", l.segmentLabelName)
		return *romanaPolicy, common.NewError("Expected segment to be specified in podSelector part as '%s'", l.segmentLabelName)
	}

	segment, err := l.getOrAddSegment(ns, kubeSegmentID)
	//	log.Printf("XXXX getOrAddSegment %s %s: %+v %v", ns, kubeSegmentID, segment, err)
	if err != nil {
		glog.Errorf("DEBUG error in translate while calling l.getOrAddSegment with %s and %s - error %s", ns, kubeSegmentID, err)
		return *romanaPolicy, err
	}
	segmentID := segment.ID
	appliedTo := common.Endpoint{TenantID: tenantID, SegmentID: segmentID}
	//	log.Printf("XXXX 0 %+v %d %d", appliedTo, tenantID, segmentID)
	//	log.Printf("XXXX 1 %+v", romanaPolicy.AppliedTo)
	romanaPolicy.AppliedTo = make([]common.Endpoint, 1)
	romanaPolicy.AppliedTo[0] = appliedTo
	//	log.Printf("XXXX 2 %+v %d expecting %+v", romanaPolicy.AppliedTo, len(romanaPolicy.AppliedTo), appliedTo)
	romanaPolicy.Peers = make([]common.Endpoint, 0)
	romanaPolicy.Rules = make([]common.Rule, 0)
	// TODO range
	// from := kubePolicy.Spec.Ingress[0].From
	// This is subject to change once the network specification in Kubernetes is finalized.
	// Right now it is a work in progress.
	glog.V(1).Infof("For %s processing %+v", kubePolicy.Metadata.Name, kubePolicy.Spec.Ingress)
	for _, ingress := range kubePolicy.Spec.Ingress {
		for _, entry := range ingress.From {
			pods := entry.Pods
			fromKubeSegmentID := pods.MatchLabels[l.segmentLabelName]
			if fromKubeSegmentID == "" {
				return *romanaPolicy, common.NewError("Expected segment to be specified in podSelector part as '%s'", l.segmentLabelName)
			}
			fromSegment, err := l.getOrAddSegment(ns, fromKubeSegmentID)
			if err != nil {
				glog.Errorf("Error in policy translator getOrAddSegment() exited with %s", err)
				return *romanaPolicy, err
			}
			peer := common.Endpoint{TenantID: tenantID, TenantExternalID: tenantExternalID, SegmentID: fromSegment.ID, SegmentExternalID: fromSegment.ExternalID}
			romanaPolicy.Peers = append(romanaPolicy.Peers, peer)
		}
		for _, toPort := range ingress.ToPorts {
			proto := strings.ToLower(toPort.Protocol)
			ports := []uint{toPort.Port}
			rule := common.Rule{Protocol: proto, Ports: ports}
			romanaPolicy.Rules = append(romanaPolicy.Rules, rule)
		}
	}
	glog.Infof("translateNetworkPolicy(): Validating %+v", romanaPolicy)
	err = romanaPolicy.Validate()
	if err != nil {
		glog.Errorf("Error in policy translator failed to validate resulting policy %v - %s", romanaPolicy, err)
		return *romanaPolicy, err
	}
	return *romanaPolicy, nil
}

type TenantCacheEntry struct {
	Tenant   tenant.Tenant
	Segments []tenant.Segment
}

func (t Translator) checkTenantInCache(tenantName string) *TenantCacheEntry {
	t.cacheMu.Lock()
	defer func() {
		t.cacheMu.Unlock()
	}()

	for tn, currentTenant := range t.tenantsCache {
		if currentTenant.Tenant.Name == tenantName {
			return &t.tenantsCache[tn]
		}
	}
	return nil
}

// Kube2Romana reserved for future use.
func (t Translator) Kube2Romana(kubePolicy KubeObject) (common.Policy, error) {
	return common.Policy{}, nil
}

// Kube2RomanaBulk attempts to translate a list of kubernetes policies into
// romana representation, returns a list of translated policies and a list
// of policies that can't be translated in original format.
func (t Translator) Kube2RomanaBulk(kubePolicies []KubeObject) ([]common.Policy, []KubeObject, error) {
	glog.Info("In Kube2RomanaBulk")
	var returnRomanaPolicy []common.Policy
	var returnKubePolicy []KubeObject

	err := t.updateCache()
	if err != nil {
		return returnRomanaPolicy, returnKubePolicy, TranslatorError{ErrorCacheUpdate, err}
	}

	for kubePolicyNumber, _ := range kubePolicies {
		romanaPolicy, err := t.translateNetworkPolicy(&kubePolicies[kubePolicyNumber])
		if err != nil {
			glog.Errorf("Error during policy translation %s", err)
			returnKubePolicy = append(returnKubePolicy, kubePolicies[kubePolicyNumber])
		} else {
			returnRomanaPolicy = append(returnRomanaPolicy, romanaPolicy)
		}
	}

	return returnRomanaPolicy, returnKubePolicy, nil

}

// checkTenantInCache checks if given tenant cache entry has a segment with given name.
func (t Translator) checkSegmentInCache(cacheEntry *TenantCacheEntry, segmentId string) *tenant.Segment {
	t.cacheMu.Lock()
	defer func() {
		t.cacheMu.Unlock()
	}()

	for segn, currentSegment := range cacheEntry.Segments {
		if currentSegment.Name == segmentId {
			return &cacheEntry.Segments[segn]
		}
	}
	return nil
}

// updateCache contacts romana Tenant service, lists
// all resources and loads them into memory.
func (t *Translator) updateCache() error {
	glog.Info("In updateCache")

	tenantURL, err := t.restClient.GetServiceUrl("tenant")
	if err != nil {
		return TranslatorError{ErrorCacheUpdate, err}
	}

	tenants := []tenant.Tenant{}
	err = t.restClient.Get(tenantURL+"/tenants", &tenants)
	if err != nil {
		return TranslatorError{ErrorCacheUpdate, err}
	}

	if t.restClient == nil {
		glog.Fatal("REST client is nil")
	}

	// tenants := []tenant.Tenant{}
	// _ = t.restClient.Find(&tenants, common.FindAll)

	t.cacheMu.Lock()
	defer func() {
		glog.Infof("Exiting updateCache with %d tenants", len(t.tenantsCache))
		t.cacheMu.Unlock()
	}()

	t.tenantsCache = nil
	for _, ten := range tenants {
		segments := []tenant.Segment{}
		fullUrl := fmt.Sprintf("%s/tenants/%d/segments", tenantURL, ten.ID)
		err = t.restClient.Get(fullUrl, &segments)

		// ignore 404 error here which means no segments
		// considered to be a zero segments rather then
		// an error.
		if err != nil && !checkHttp404(err) {
			return TranslatorError{ErrorCacheUpdate, err}
		}

		t.tenantsCache = append(t.tenantsCache, TenantCacheEntry{ten, segments})
	}
	return nil
}

func checkHttp404(err error) (ret bool) {
	switch e := err.(type) {
	case common.HttpError:
		if e.StatusCode == 404 {
			ret = true
		}
	}

	return
}

func (t *Translator) Init(client *common.RestClient, segmentLabelName string) {

	t.restClient = client
	err := t.updateCache()
	if err == nil {
		glog.Infof("Translator cache updated - have %d tenant entries", len(t.tenantsCache))
	} else {
		glog.Errorf("Translator cache update failed, %s", err)
	}

	t.cacheMu = sync.Mutex{}
	t.segmentLabelName = segmentLabelName
}

func (t Translator) GetClient() *common.RestClient {
	return t.restClient
}

type TranslatorError struct {
	Code    TranslatorErrorType
	Details error
}

func (t TranslatorError) Error() string {
	return fmt.Sprintf("Translator error code %d, %s", t.Code, t.Details)
}

type TranslatorErrorType int

const (
	ErrorCacheUpdate TranslatorErrorType = iota
	ErrorTenantNotIntCache
)
