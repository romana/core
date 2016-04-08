// Copyright (c) 2016 Pani Networks
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

package rsearch

import (
	"bytes"
	"encoding/json"
	"gopkg.in/gcfg.v1"
	"testing"
	"time"
)

func TestResoureProcessor(t *testing.T) {
	config := Config{}
	err := gcfg.ReadStringInto(&config, cfgStr)
	if err != nil {
		t.Errorf("Failed to parse gcfg data: %s", err)
	}

	done := make(chan Done)
	events := make(chan Event)

	req := Process(events, done, config)
	time.Sleep(time.Duration(1 * time.Second))

	var e Event
	policyReader := bytes.NewBufferString(testPolicy)
	dec := json.NewDecoder(policyReader)
	dec.Decode(&e)

	events <- e

	responseChannel := make(chan SearchResponse)
	searchRequest := SearchRequest{Tag: "tier=backend#", Resp: responseChannel}
	req <- searchRequest

	result, ok := <-searchRequest.Resp
	if !ok {
		t.Error("Response channel in SearchRequest object found unexpectedly closed")
	}

	if len(result) == 0 {
		t.Error("Search request is empty - expecting one result")
	}

	if result[0].Metadata.Name != "pol1" {
		t.Error("Unexpected search response = expect policy name = pol1, got ", result[0].Metadata.Name)
	}
}
