package agent

import (
	"github.com/romana/core/common"
)

type agentStore struct {
	common.DbStore
}

func (agentStore *agentStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = new(Route)
	retval[1] = new(NetworkInterface)
	return retval
}

type Route struct {
	ID     uint64 `sql:"AUTO_INCREMENT"`
	IP     string
	Mask   string
	Kind   targetKind
	Spec   string
	status string
}

type targetKind string

const (
	device  targetKind = "dev"
	gateway targetKind = "gw"
)

type NetworkInterface struct {
	ID     uint64 `sql:"AUTO_INCREMENT"`
	Name   string
	Status string
}

func (agentStore *agentStore) CreateSchemaPostProcess() error {
	return nil
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
