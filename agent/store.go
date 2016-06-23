package agent

import (
	"github.com/golang/glog"
	"github.com/romana/core/common"
	"github.com/romana/core/pkg/util/firewall"
	"sync"
)

// agentStore is a backing storage. Agent will likely use
// sqlite which is not very reliable in concurrent access scenario,
// so we are going to guard access with mutex.
type agentStore struct {
	common.DbStore
	mu *sync.Mutex
}

// GetDb implements firewall.FirewallStore
func (agentStore agentStore) GetDb() common.DbStore {
	return agentStore.DbStore
}

// GetMutex implements firewall.FirewallStore
func (agentStore agentStore) GetMutex() *sync.Mutex {
	return agentStore.mu
}

// Entities implements Entities method of
// Service interface.
func (agentStore *agentStore) Entities() []interface{} {
	retval := make([]interface{}, 3)
	retval[0] = new(Route)
	retval[1] = new(NetworkInterface)
	retval[2] = new(firewall.IPtablesRule)
	return retval
}

// NewStore returns initialized agentStore.
func NewStore(config common.ServiceConfig) *agentStore {
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	store := agentStore{
		mu: &sync.Mutex{},
	}
	store.ServiceStore = &store
	store.SetConfig(storeConfig)

	return &store
}

// Route is a model to store managed routes
type Route struct {
	ID     uint64 `sql:"AUTO_INCREMENT"`
	IP     string
	Mask   string
	Kind   targetKind
	Spec   string
	Status string
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

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (agentStore *agentStore) CreateSchemaPostProcess() error {
	return nil
}

func (agentStore *agentStore) deleteNetworkInterface(iface *NetworkInterface) error {
	glog.V(1).Info("Acquiring store mutex for deleteNetworkInterface")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for deleteNetworkInterface")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for deleteNetworkInterface")

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
	glog.V(1).Info("Acquiring store mutex for findNetworkInterface")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for findNetworkInterface")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for findNetworkInterface")

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
	glog.V(1).Info("Acquiring store mutex for addNetworkInterface")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for addNetworkInterface")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for addNetworkInterface")

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
	glog.V(1).Info("Acquiring store mutex for listNetworkInterfaces")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for listNetworkInterfaces")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for listNetworkInterfaces")

	var networkInterfaces []NetworkInterface
	agentStore.DbStore.Db.Find(&networkInterfaces)
	err := common.MakeMultiError(agentStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return networkInterfaces, nil
}
