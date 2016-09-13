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
	mu *sync.RWMutex
}

// GetDb implements firewall.FirewallStore
func (agentStore agentStore) GetDb() common.DbStore {
	return agentStore.DbStore
}

// GetMutex implements firewall.FirewallStore
func (agentStore agentStore) GetMutex() *sync.RWMutex {
	return agentStore.mu
}

// Entities implements Entities method of
// Service interface.
func (agentStore *agentStore) Entities() []interface{} {
	retval := make([]interface{}, 3)
	retval[0] = new(Route)
	retval[1] = new(firewall.IPtablesRule)
	retval[2] = new(NetIf)
	return retval
}

// NewStore returns initialized agentStore.
func NewStore(config common.ServiceConfig) *agentStore {
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	store := agentStore{
		mu: &sync.RWMutex{},
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

// CreateSchemaPostProcess implements CreateSchemaPostProcess method of
// Service interface.
func (agentStore *agentStore) CreateSchemaPostProcess() error {
	return nil
}

func (agentStore *agentStore) deleteRoute(route *Route) error {
	glog.V(1).Info("Acquiring store mutex for deleteRoute")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for deleteRoute")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for deleteRoute")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Delete(route)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}

	return nil
}

func (agentStore *agentStore) findRouteByIface(routeIface string) (*Route, error) {
	glog.V(1).Info("Acquiring store mutex for findRoute")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for findRoute")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for findRoute")

	var route Route
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Where("ip = ?", routeIface).First(&route)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return nil, err
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &route, nil
}

func (agentStore *agentStore) addNetIf(netif *NetIf) error {
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Create(netif)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

func (agentStore *agentStore) findNetIf(netif *NetIf) error {
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Where(netif).First(netif)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

func (agentStore *agentStore) listNetIfs() ([]NetIf, error) {
	db := agentStore.DbStore.Db
	var netifs []NetIf
	agentStore.DbStore.Db.Find(&netifs)
	err := common.GetDbErrors(db)
	if err != nil {
		return nil, err
	}
	return netifs, nil
}

func (agentStore *agentStore) deleteNetIf(netif *NetIf) error {
	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Delete(netif)
	err := common.GetDbErrors(db)
	if err != nil {
		return err
	}
	return nil
}

func (agentStore *agentStore) addRoute(route *Route) error {
	glog.V(1).Info("Acquiring store mutex for addRoute")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for addRoute")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for addRoute")

	db := agentStore.DbStore.Db
	agentStore.DbStore.Db.Create(route)
	if db.Error != nil {
		return db.Error
	}
	agentStore.DbStore.Db.NewRecord(*route)
	err := common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}
	if db.Error != nil {
		return db.Error
	}
	return nil
}

func (agentStore *agentStore) listRoutes() ([]Route, error) {
	glog.V(1).Info("Acquiring store mutex for listRoutes")
	agentStore.mu.Lock()
	defer func() {
		glog.V(1).Info("Releasing store mutex for listRoutes")
		agentStore.mu.Unlock()
	}()
	glog.V(1).Info("Acquired store mutex for listRoutes")

	var routes []Route
	agentStore.DbStore.Db.Find(&routes)
	err := common.MakeMultiError(agentStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return routes, nil
}
