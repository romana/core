package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/romana/core/common/api"
	"github.com/romana/rlog"
)

const mockHostsFile = "/tmp/agentmockhosts.json"
const mockBlockFile = "/tmp/agentmockblocks.json"

type MockClient struct{}

func (MockClient) ListHosts() api.HostList {
	var hosts api.HostList

	data, err := ioutil.ReadFile(mockHostsFile)
	if err != nil {
		rlog.Errorf("failed to read mockfile for hosts")
		return hosts
	}

	err = json.Unmarshal(data, &hosts)
	if err != nil {
		rlog.Errorf("failed to read mockfile for hosts")
	}
	return hosts
}

func (MockClient) ListAllBlocks() *api.IPAMBlocksResponse {
	var blocks api.IPAMBlocksResponse

	data, err := ioutil.ReadFile(mockBlockFile)
	if err != nil {
		rlog.Errorf("failed to read mockfile for blocks")
		return &blocks
	}

	err = json.Unmarshal(data, &blocks)
	if err != nil {
		rlog.Errorf("failed to parse mockfile for blocks, err=%s", err)
	}
	return &blocks
}

func (c MockClient) WatchBlocks(stopCh <-chan struct{}) (res <-chan api.IPAMBlocksResponse, err error) {
	return res, nil
}

func (c MockClient) WatchHosts(stopCh <-chan struct{}) (res <-chan api.HostList, err error) {
	return res, nil
}
