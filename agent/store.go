package agent

import (
	"github.com/golang/glog"
	"github.com/romana/core/common"
	"sync"
)

// agentStore is a backing storage. Agent will likely use
// sqlite which is not very reliable in concurrent access scenario,
// so we are going to serialize access with mutex.
type agentStore struct {
	common.DbStore
	mu sync.Mutex
}

// Entities implements Entities method of
// Service interface.
func (agentStore *agentStore) Entities() []interface{} {
	retval := make([]interface{}, 3)
	retval[0] = new(Route)
	retval[1] = new(NetworkInterface)
	retval[2] = new(IPtablesRule)
	return retval
}

// Route is a model to store managed routes
type Route struct {
	ID     uint64 `sql:"AUTO_INCREMENT"`
	IP     string
	Mask   string
	Kind   targetKind
	Spec   string
	status string
}

// targetKind is a an IP route destination type.
type targetKind string

const (
	device  targetKind = "dev"
	gateway targetKind = "gw"
)

// NetworkInterface is a model to store managed network interfaces.
type NetworkInterface struct {
	ID     uint64 `sql:"AUTO_INCREMENT"`
	Name   string
	Status string
}

// IPtablesRule represents a single iptables rule managed by the agent.
type IPtablesRule struct {
	ID    uint64 `sql:"AUTO_INCREMENT"`
	Body  string
	State string
}

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (agentStore *agentStore) CreateSchemaPostProcess() error {
	return nil
}

func (agentStore *agentStore) deleteNetworkInterface(iface *NetworkInterface) error {
	glog.Info("Acquiring store mutex for deleteNetworkInterface")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for deleteNetworkInterface")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for deleteNetworkInterface")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Delete(iface)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}

	return nil
}

func (agentStore *agentStore) findNetworkInterface(ifaceName string) (*NetworkInterface, error) {
	glog.Info("Acquiring store mutex for findNetworkInterface")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for findNetworkInterface")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for findNetworkInterface")

	var iface NetworkInterface
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Where("name = ?", ifaceName).First(&iface)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &iface, nil
}

func (agentStore *agentStore) addNetworkInterface(iface *NetworkInterface) error {
	glog.Info("Acquiring store mutex for addNetworkInterface")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for addNetworkInterface")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for addNetworkInterface")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Create(iface)
	if db.Error != nil {
		return db.Error
	}
	agentStore.DbStore.Db.NewRecord(*iface)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}
	return nil
}

func (agentStore *agentStore) listNetworkInterfaces() ([]NetworkInterface, error) {
	glog.Info("Acquiring store mutex for listNetworkInterfaces")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for listNetworkInterfaces")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for listNetworkInterfaces")

	var networkInterfaces []NetworkInterface
	agentStore.DbStore.Db.Find(&networkInterfaces)
	err := common.MakeMultiError(agentStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return networkInterfaces, nil
}

func (agentStore *agentStore) addIPtablesRule(rule *IPtablesRule) error {
	glog.Info("Acquiring store mutex for addNetworkInterface")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for addNetworkInterface")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for addNetworkInterface")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Create(rule)
	if db.Error != nil {
		return db.Error
	}
	agentStore.DbStore.Db.NewRecord(*rule)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}
	return nil
}

func (agentStore *agentStore) listIPtablesRules() ([]IPtablesRule, error) {
	glog.Info("Acquiring store mutex for listIPtablesRules")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for listIPtablesRules")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for listIPtablesRules")

	var iPtablesRule []IPtablesRule
	agentStore.DbStore.Db.Find(&iPtablesRule)
	err := common.MakeMultiError(agentStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return iPtablesRule, nil
}

func (agentStore *agentStore) deleteIPtablesRule(rule *IPtablesRule) error {
	glog.Info("Acquiring store mutex for deleteIPtablesRule")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for deleteIPtablesRule")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for deleteIPtablesRule")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Delete(rule)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}

	return nil
}

func (agentStore *agentStore) findIPtablesRules(subString string) (*[]IPtablesRule, error) {
	glog.Info("Acquiring store mutex for findIPtablesRule")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for findIPtablesRule")
		agentStore.mu.Unlock()
	}()
	glog.Info("Acquired store mutex for findIPtablesRule")

	var rules []IPtablesRule
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Where("body LIKE = %?%", subString).Find(&rules)
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
func (agentStore *agentStore) switchIPtablesRule(rule *IPtablesRule, op opSwitchIPtables) error {

	// Fast track return if nothing to be done
	if rule.State == op.String() {
		glog.Infof("switchIPtablesRule nothing to be done for %s", rule.State)
		return nil
	}

	glog.Info("Acquiring store mutex for switchIPtablesRule")
	agentStore.mu.Lock()
	defer func() {
		glog.Info("Releasing store mutex for switchIPtablesRule")
		agentStore.mu.Unlock()
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

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Save(rule)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}

	return nil
}
