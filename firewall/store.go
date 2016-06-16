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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package firewall

import (
	"github.com/golang/glog"
	"github.com/romana/core/common"
	"sync"
)

type firewallStore struct {
	common.DbStore
	mu sync.Mutex
}

// Entities implements Entities method of
// Service interface.
func (firewallStore *firewallStore) Entities() []interface{} {
	retval := make([]interface{}, 1)
	retval[0] = new(IPtablesRule)
	return retval
}

// CreateSchemaPostProcess implements  common.ServiceStore.CreateSchemaPostProcess()
func (fs firewallStore) CreateSchemaPostProcess() error {
	return nil
}

// IPtablesRule represents a single iptables rule managed by the agent.
// TODO rename FirewallRule
type IPtablesRule struct {
	ID    uint64 `sql:"AUTO_INCREMENT"`
	Body  string
	State string
}

func (firewallStore *firewallStore) addIPtablesRule(rule *IPtablesRule) error {
	glog.Info("Acquiring store mutex for addIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for addIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for addIPtablesRule")

	db := firewallStore.DbStore.Db
	firewallStore.DbStore.Db.Create(rule)
	if db.Error != nil {
		return db.Error
	}
	firewallStore.DbStore.Db.NewRecord(*rule)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}
	return nil
}

func (firewallStore *firewallStore) listIPtablesRules() ([]IPtablesRule, error) {
	glog.Info("Acquiring store mutex for listIPtablesRules")
	firewallStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for listIPtablesRules")
		firewallStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for listIPtablesRules")

	var iPtablesRule []IPtablesRule
	firewallStore.DbStore.Db.Find(&iPtablesRule)
	err := common.MakeMultiError(firewallStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return iPtablesRule, nil
}

func (firewallStore *firewallStore) deleteIPtablesRule(rule *IPtablesRule) error {
	glog.Info("Acquiring store mutex for deleteIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for deleteIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for deleteIPtablesRule")

	db := firewallStore.DbStore.Db
	firewallStore.DbStore.Db.Delete(rule)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}

	return nil
}

func (firewallStore *firewallStore) findIPtablesRules(subString string) (*[]IPtablesRule, error) {
	glog.Info("Acquiring store mutex for findIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for findIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for findIPtablesRule")

	var rules []IPtablesRule
	db := firewallStore.DbStore.Db
	firewallStore.DbStore.Db.Where("body LIKE = %?%", subString).Find(&rules)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &rules, nil
}

// opSwitchIPtables represents action to be taken in switchIPtablesRule
type opSwitchIPtables int

const (
	setRuleActive opSwitchIPtables = iota
	setRuleInactive
	toggleRule
)

func (op opSwitchIPtables) String() string {
	var result string

	switch op {
	case setRuleActive:
		result = "active"
	case setRuleInactive:
		result = "inactive"
	case toggleRule:
		result = "toggleRule"
	}

	return result
}

// switchIPtablesRule changes IPtablesRule state.
func (firewallStore *firewallStore) switchIPtablesRule(rule *IPtablesRule, op opSwitchIPtables) error {

	// Fast track return if nothing to be done
	if rule.State == op.String() {
		glog.Infof("switchIPtablesRule nothing to be done for %s", rule.State)
		return nil
	}

	glog.Info("Acquiring store mutex for switchIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for switchIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for switchIPtablesRule")

	// if toggle requested then reverse current state
	if op == toggleRule {
		if rule.State == setRuleInactive.String() {
			rule.State = setRuleActive.String()
		} else {
			rule.State = setRuleInactive.String()
		}
		// otherwise just assign op value
	} else {
		rule.State = op.String()
	}

	db := firewallStore.DbStore.Db
	firewallStore.DbStore.Db.Save(rule)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}

	return nil
}
