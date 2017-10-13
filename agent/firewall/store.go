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
	"database/sql"
	"sync"

	log "github.com/romana/rlog"
)

// FirewallStore defines how database should be passed into firewall instance.
type FirewallStore interface {
	// GetDb Returns fully initialized DbStore object
	GetDb() *sql.DB

	// GetMutex return instance of mutex used guard firewall database.
	GetMutex() *sync.RWMutex
}

// firewallStore implement FirewallStore
type firewallStore struct {
	db *sql.DB
	mu *sync.RWMutex
}

// GetMutex implements firewall.FirewallStore
func (fs firewallStore) GetMutex() *sync.RWMutex {
	return fs.mu
}

// GetMutex implements firewall.FirewallStore
func (fs firewallStore) GetDB() *sql.DB {
	return fs.db
}

// IPtablesRule represents a single iptables rule managed by the agent.
type IPtablesRule struct {
	//	ID    uint64 `sql:"AUTO_INCREMENT"`
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

	db := firewallStore.db
	// db := firewallStore.GetDb()
	log.Info("In addIPtablesRule() after GetDb")
	if db == nil {
		panic("In addIPtablesRule(), db is nil")
	}

	st, err := db.Prepare("INSERT INTO iptables_rules (body, state) VALUES (?,?)")
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec(rule.Body, rule.State)
	return err
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

	rows, err := firewallStore.db.Query("SELECT body, state FROM iptables_rules")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]IPtablesRule, 0)
	for rows.Next() {
		rule := IPtablesRule{}
		err := rows.Scan(&rule.Body, &rule.State)
		if err != nil {
			return rules, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
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

	st, err := firewallStore.db.Prepare(`INSERT INTO iptables_rules (body, state) 
		SELECT ?, ? WHERE NOT EXISTS(SELECT 1 from iptables_rules where body=?)`)
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return err
	}
	_, err = st.Exec(rule.Body, rule.State, rule.Body)
	if err != nil {
		return err
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

	db := firewallStore.db

	st, err := db.Prepare("DELETE FROM iptables_rules WHERE body = ?")
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return err
	}
	_, err = st.Exec(rule.Body)
	return err
}

func (firewallStore *firewallStore) findIPtablesRules(subString string) (*[]IPtablesRule, error) {
	log.Info("Acquiring store mutex for findIPtablesRule")
	firewallStore.mu.Lock()
	defer func() {
		log.Info("Releasing store mutex for findIPtablesRule")
		firewallStore.mu.Unlock()
	}()
	log.Info("Acquired store mutex for findIPtablesRule")

	db := firewallStore.db

	st, err := db.Prepare("SELECT body, state FROM iptables_rules WHERE body LIKE ?")
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return nil, err
	}
	rules := make([]IPtablesRule, 0)

	searchString := "%" + subString + "%"
	rows, err := st.Query(searchString)
	if rows != nil {
		defer rows.Close()
	}
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		rule := IPtablesRule{}
		err = rows.Scan(&rule.Body, &rule.State)
		if err != nil {
			return &rules, err
		}
		rules = append(rules, rule)
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

	db := firewallStore.db
	st, err := db.Prepare("UPDATE iptables_rules SET state =  ? WHERE body = ?")
	if st != nil {
		defer st.Close()
	}
	if err != nil {
		return err
	}
	_, err = st.Exec(rule.State, rule.Body)
	if err != nil {
		return err
	}
	return nil
}
