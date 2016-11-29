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
//
// Backing store for firewall.

package firewall

import (
	"github.com/romana/core/common"
	log "github.com/romana/rlog"
	"sync"
)

// FirewallStore defines how database should be passed into firewall instance.
type FirewallStore interface {
	// GetDb Returns fully initialized DbStore object
	GetDb() common.DbStore

	// GetMutex return instance of mutex used guard firewall database.
	GetMutex() *sync.RWMutex
}

// firewallStore implement FirewallStore
type firewallStore struct {
	common.DbStore
	mu *sync.RWMutex
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

// GetDb implements firewall.FirewallStore
func (fs firewallStore) GetDb() common.DbStore {
	return fs.DbStore
}

// GetMutex implements firewall.FirewallStore
func (fs firewallStore) GetMutex() *sync.RWMutex {
	return fs.mu
}

// IPtablesRule represents a single iptables rule managed by the agent.
type IPtablesRule struct {
	ID    uint64 `sql:"AUTO_INCREMENT"`
	Body  string
	State string
}

// GetBody implements FirewallRule interface.
func (r *IPtablesRule) GetBody() string {
	return r.Body
}

// GetType implements FirewallRule interface.
func (r *IPtablesRule) GetType() string {
	return "iptables"
}

// SetBody implements FirewallRule interface
func (r *IPtablesRule) SetBody(body string) {
	r.Body = body
}

func (firewallStore *firewallStore) addIPtablesRule(rule *IPtablesRule) error {
	log.Info("Acquiring store mutex for addIPtablesRule")
	if rule == nil {
		panic("In addIPtablesRule(), received nil rule")
	}

	firewallStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for addIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for addIPtablesRule")

	err := firewallStore.addIPtablesRuleUnsafe(rule)
	return err
}

// addIPtablesRuleUnsafe is a non thread safe implementation of addIPtablesRule.
// Unsafe implementation is needed for functions which are already managing same mutex.
func (firewallStore *firewallStore) addIPtablesRuleUnsafe(rule *IPtablesRule) error {

	db := firewallStore.DbStore.Db
	// db := firewallStore.GetDb()
	log.Info("In addIPtablesRule() after GetDb")
	if db == nil {
		panic("In addIPtablesRule(), db is nil")
	}

	firewallStore.DbStore.Db.Create(rule)
	log.Info("In addIPtablesRule() after Db.Create")
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

// listIPtablesRules returns a list of all firewall rules in a database.
func (firewallStore *firewallStore) listIPtablesRules() ([]IPtablesRule, error) {
	log.Info("Acquiring store mutex for listIPtablesRules")
	firewallStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for listIPtablesRules")
		firewallStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for listIPtablesRules")

	var iPtablesRule []IPtablesRule
	firewallStore.DbStore.Db.Find(&iPtablesRule)
	err := common.MakeMultiError(firewallStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return iPtablesRule, nil
}

// ensureIPtablesRule checks if given rule exists in a database and if not, creates it.
func (firewallStore *firewallStore) ensureIPtablesRule(rule *IPtablesRule) error {
	log.Info("Acquiring store mutex for listIPtablesRules")
	firewallStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for listIPtablesRules")
		firewallStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for listIPtablesRules")

	if firewallStore.DbStore.Db.Where("body = ?", rule.Body).First(rule).RecordNotFound() {
		log.Tracef(2, "In ensureIPtablesRule(), rule %s not found in db - creating", rule.Body)
		err0 := firewallStore.addIPtablesRuleUnsafe(rule)
		if err0 != nil {
			log.Errorf("In ensureIPtablesRule() failed to store rule %v", rule)
			return err0
		}
	} else {
		log.Tracef(2, "In ensureIPtablesRule(), rule %s already in db - nothing to do", rule.Body)
	}

	return nil
}

// deleteIPtablesRule deletes firewall rules from database.
func (firewallStore *firewallStore) deleteIPtablesRule(rule *IPtablesRule) error {
	log.Info("Acquiring store mutex for deleteIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for deleteIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for deleteIPtablesRule")

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
	log.Info("Acquiring store mutex for findIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for findIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for findIPtablesRule")

	var rules []IPtablesRule
	db := firewallStore.DbStore.Db
	searchString := "%" + subString + "%"
	firewallStore.DbStore.Db.Where("body LIKE ?", searchString).Find(&rules)
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
		log.Infof("switchIPtablesRule nothing to be done for %s", rule.State)
		return nil
	}

	log.Info("Acquiring store mutex for switchIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for switchIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for switchIPtablesRule")

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
