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
	cacheMu          *sync.Mutex
	segmentLabelName string
}

func (t *Translator) Init(client *common.RestClient, segmentLabelName string) {
	t.cacheMu = &sync.Mutex{}
	t.restClient = client
	err := t.updateCache()
	if err == nil {
		glog.Infof("Translator cache updated - have %d tenant entries", len(t.tenantsCache))
	} else {
		glog.Errorf("Translator cache update failed, %s", err)
	}
	t.segmentLabelName = segmentLabelName
}

func (t Translator) GetClient() *common.RestClient {
	return t.restClient
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

// translateNetworkPolicy translates a Kubernetes policy into
// Romana policy (see common.Policy) with the following rules:
// 1. Kubernetes Namespace corresponds to Romana Tenant
// 2. If Romana Tenant does not exist it is an error (a tenant should
//    automatically have been created when the namespace was added)
func (l *Translator) translateNetworkPolicy(kubePolicy *KubeObject) (common.Policy, error) {
	policyName := fmt.Sprintf("kube.%s.%s", kubePolicy.Metadata.Namespace, kubePolicy.Metadata.Name)
	romanaPolicy := &common.Policy{Direction: common.PolicyDirectionIngress, Name: policyName, ExternalID: kubePolicy.Metadata.Uid}

	// Prepare translate group with original kubernetes policy and empty romana policy.
	translateGroup := &TranslateGroup{kubePolicy, romanaPolicy, TranslateGroupStartIndex}

	// Fill in AppliedTo field of romana policy.
	err := translateGroup.translateTarget(l)
	if err != nil {
		return *translateGroup.romanaPolicy, TranslatorError{ErrorTranslatingPolicyTarget, err}
	}

	// For each Ingress field in kubernetes policy, create Peer and Rule fields in
	// romana policy.
	for {
		err := translateGroup.translateNextIngress(l)
		if _, ok := err.(NoMoreIngressEntities); ok {
			break
		}

		if err != nil {
			return *translateGroup.romanaPolicy, TranslatorError{ErrorTranslatingPolicyIngress, err}
		}
	}

	return *translateGroup.romanaPolicy, nil
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
		return nil, TranslatorError{ErrorTenantNotInCache, fmt.Errorf("Tenant not found in cache while resolving segment")}
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
	ErrorTenantNotInCache
	ErrorTranslatingPolicyTarget
	ErrorTranslatingPolicyIngress
)

// TranslateGroup represent a state of translation of kubernetes policy
// into romana policy.
type TranslateGroup struct {
	kubePolicy   *KubeObject
	romanaPolicy *common.Policy
	ingressIndex int
}

const TranslateGroupStartIndex = 0

// translateTarget analizes kubePolicy and fills romanaPolicy.AppliedTo field.
func (tg *TranslateGroup) translateTarget(translator *Translator) error {

	// Translate kubernetes namespace into romana tenant. Must be defined.
	tenantCacheEntry := translator.checkTenantInCache(tg.kubePolicy.Metadata.Namespace)
	if tenantCacheEntry == nil {
		glog.Errorf("Tenant not found when translating policy %v", tg.romanaPolicy)
		return TranslatorError{ErrorTenantNotInCache, nil}
	}

	// Empty PodSelector means policy applied to the entire namespace.
	if len(tg.kubePolicy.Spec.PodSelector.MatchLabels) == 0 {
		tg.romanaPolicy.AppliedTo = []common.Endpoint{
			common.Endpoint{TenantID: tenantCacheEntry.Tenant.ID, TenantExternalID: tenantCacheEntry.Tenant.ExternalID},
		}

		glog.V(2).Infof("Segment was not specified in policy %v, assuming target is a namespace", tg.kubePolicy)
		return nil
	}

	// If PodSelector is not empty then segment label must be defined.
	kubeSegmentID, ok := tg.kubePolicy.Spec.PodSelector.MatchLabels[translator.segmentLabelName]
	if !ok || kubeSegmentID == "" {
		glog.Errorf("Expected segment to be specified in podSelector part as %s", translator.segmentLabelName)
		return common.NewError("Expected segment to be specified in podSelector part as '%s'", translator.segmentLabelName)
	}

	// Translate kubernetes segment label into romana segment.
	segment, err := translator.getOrAddSegment(tg.kubePolicy.Metadata.Namespace, kubeSegmentID)
	if err != nil {
		glog.Errorf("Error in translate while calling l.getOrAddSegment with %s and %s - error %s", tg.kubePolicy.Metadata.Namespace, kubeSegmentID, err)
		return err
	}

	tg.romanaPolicy.AppliedTo = []common.Endpoint{
		common.Endpoint{TenantID: tenantCacheEntry.Tenant.ID, TenantExternalID: tenantCacheEntry.Tenant.ExternalID, SegmentID: segment.ID},
	}

	return nil
}

/// makeNextIngressPeer analyzes current Ingress rule and adds new Peer to romanaPolicy.Peers.
func (tg *TranslateGroup) makeNextIngressPeer(translator *Translator) error {
	ingress := tg.kubePolicy.Spec.Ingress[tg.ingressIndex]

	// Translate kubernetes namespace into romana tenant. Must be defined.
	// TODO instead of relying on target tenant we should first check if
	// NamespaceSelector defined in current Ingress rule. Stas.
	tenantCacheEntry := translator.checkTenantInCache(tg.kubePolicy.Metadata.Namespace)
	if tenantCacheEntry == nil {
		glog.Errorf("Tenant not not found when translating policy %v", tg.romanaPolicy)
		return TranslatorError{ErrorTenantNotInCache, nil}
	}

	for _, fromEntry := range ingress.From {
		// Empty PodSelector means traffic is allowed from any pod in a namespace.
		if len(fromEntry.Pods.MatchLabels) == 0 {
			tg.romanaPolicy.Peers = append(tg.romanaPolicy.Peers,
				common.Endpoint{TenantID: tenantCacheEntry.Tenant.ID, TenantExternalID: tenantCacheEntry.Tenant.ExternalID})

			glog.V(2).Infof("No segment specified when translating ingress rule %v", tg.kubePolicy.Spec.Ingress[tg.ingressIndex])
			return nil
		}

		// If PodSelector is not empty then segment label must be defined.
		kubeSegmentID, ok := fromEntry.Pods.MatchLabels[translator.segmentLabelName]
		if !ok || kubeSegmentID == "" {
			glog.Errorf("Expected segment to be specified in podSelector part as %s", translator.segmentLabelName)
			return common.NewError("Expected segment to be specified in podSelector part as '%s'", translator.segmentLabelName)
		}

		// Translate kubernetes segment label into romana segment.
		segment, err := translator.getOrAddSegment(tenantCacheEntry.Tenant.Name, kubeSegmentID)
		if err != nil {
			glog.Errorf("Error in translate while calling l.getOrAddSegment with %s and %s - error %s", tenantCacheEntry.Tenant.Name, kubeSegmentID, err)
			return err
		}

		tg.romanaPolicy.Peers = append(tg.romanaPolicy.Peers,
			common.Endpoint{TenantID: tenantCacheEntry.Tenant.ID, TenantExternalID: tenantCacheEntry.Tenant.ExternalID, SegmentID: segment.ID})

	}
	return nil
}

// makeNextRule analizes current ingress rule and adds a new Rule to romanaPolicy.Rules.
func (tg *TranslateGroup) makeNextRule(translator *Translator) error {
	ingress := tg.kubePolicy.Spec.Ingress[tg.ingressIndex]

	for _, toPort := range ingress.ToPorts {
		proto := strings.ToLower(toPort.Protocol)
		ports := []uint{toPort.Port}
		rule := common.Rule{Protocol: proto, Ports: ports}
		tg.romanaPolicy.Rules = append(tg.romanaPolicy.Rules, rule)
	}

	return nil
}

// translateNextIngress translates next Ingress object from kubePolicy into romanaPolicy
// Peer and Rule fields.
func (tg *TranslateGroup) translateNextIngress(translator *Translator) error {

	if tg.ingressIndex > len(tg.kubePolicy.Spec.Ingress)-1 {
		return NoMoreIngressEntities{}
	}

	// Translate Ingress.From into romanaPolicy.ToPorts.
	err := tg.makeNextIngressPeer(translator)
	if err != nil {
		return err
	}

	// Translate Ingress.Ports into romanaPolicy.Rules.
	err = tg.makeNextRule(translator)
	if err != nil {
		return err
	}

	tg.ingressIndex++

	return nil
}

// NoMoreIngressEntities is an error that indicates that translateNextIngress
// went through all Ingress entries in TranslateGroup.kubePolicy.
type NoMoreIngressEntities struct{}

func (e NoMoreIngressEntities) Error() string {
	return "Done translating"
}
