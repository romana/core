package agent

import (
	"github.com/romana/core/common"
)

// agentStore is a backing storage
type agentStore struct {
	common.DbStore
}

// Entities implements Entities method of
// Service interface.
func (agentStore *agentStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = new(Route)
	retval[1] = new(NetworkInterface)
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

// NetworkInterface is a model to store managed network interfaces
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
	var networkInterfaces []NetworkInterface
	agentStore.DbStore.Db.Find(&networkInterfaces)
	err := common.MakeMultiError(agentStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return networkInterfaces, nil
}
