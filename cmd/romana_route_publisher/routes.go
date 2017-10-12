// Copyright (c) 2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package main

import (
	"net"

	"github.com/romana/core/agent/router/publisher"
	"github.com/romana/core/common/api"
	log "github.com/romana/rlog"
)

// createRouteToBlocks loops over list of blocks and creates routes when needed.
func createRouteToBlocks(blocks []api.IPAMBlockResponse, args map[string]interface{}, hostname string, bird publisher.Interface) {
	var networks []net.IPNet

	for _, block := range blocks {
		if block.Host != hostname {
			log.Tracef(4, "Block %v is remote and should not be advertised", block)
			continue
		}

		networks = append(networks, block.CIDR.IPNet)
	}

	err := bird.Update(networks, args)
	if err != nil {
		log.Error(err)
	}
}
