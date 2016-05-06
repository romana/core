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

package kubernetes

import (
	"bytes"
	"encoding/json"
	"github.com/romana/core/common"
	//	"gopkg.in/gcfg.v1"
	"testing"
	"time"
)

func TestResourceProcessor(t *testing.T) {

	done := make(chan Done)
	events := make(chan Event)

	l := kubeListener{}
	cfg := common.ServiceConfig{}
	cfg.ServiceSpecific = make(map[string]interface{})
	cfg.ServiceSpecific["url_prefix"] = "apis/romana.io/demo/v1/namespaces"
	cfg.ServiceSpecific["segment_label_name"] = "tier"
	cfg.ServiceSpecific["kubernetes_url"] = "http://192.168.0.10:8080"
	err := l.SetConfig(cfg)
	if err != nil {
		t.Error(err.Error())
	}
	l.process(events, done)
	time.Sleep(time.Duration(1 * time.Second))

	var e Event
	policyReader := bytes.NewBufferString(addPolicy1)
	dec := json.NewDecoder(policyReader)
	dec.Decode(&e)

	events <- e

}
