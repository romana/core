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

// Listens to Kubernetes for policy updates
package kubernetes

import (
	//	"bufio"
	"bytes"
	//	"fmt"
	"io"
	"strings"
	"encoding/json"
	"log"
	"sync"
	"time"
	//	"io/ioutil"
	"net/http"
	//	"net/http/httputil"
	"runtime"
)

// readChunk reads the next chunk from the provided reader.
func readChunk(reader io.Reader) ([]byte, error) {
	result := make([]byte, 0)
	for {
		buf := make([]byte, bytes.MinRead)
		n, err := reader.Read(buf)
		if n < bytes.MinRead {
			result = append(result, buf[0:n]...)
			if err != nil {
				return result, err
			} else {
				break
			}
		}
		result = append(result, buf...)
	}
	return result, nil
}

// listen connects to kubernetesURL and sends each
// chunk received to the ch channel. It exits on an
// error.
func listen(ch chan []byte, kubernetesURL string) {
	log.Printf("Listening to %s, currently %d goroutines are running", kubernetesURL, runtime.NumGoroutine())
	resp, err := http.Get(kubernetesURL)
	if err != nil {
		log.Printf("Error connecting: %v", err)
		log.Println("Closing channel")
		close(ch)
		log.Println("Exiting goroutine")
		return
	}
	//	chunkedReader := resp.Body
	for {
		chunk, err := readChunk(resp.Body)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading chunk: %v", err)
			}
			if chunk != "" {
				ch <- chunk
			}
			log.Println("Closing channel")
			close(ch)
			log.Println("Exiting goroutine")
			return
		}
		if chunk == "" {
			time.Sleep(1 * time.Millisecond)
		} else {
			ch <- chunk
		}
	}
}


// processChunk processes a chunk received from Kubernetes. A chunk
// is a new update.
func processChunk(chunk []byte) error {
	m := make(map[string]interface{})
	err := json.Unmarshal(chunk, &m)
	if err != nil {
		return err
	}
	method := m["method"]
	if method == nil {
		return errors.New("Expected 'method' field")
	}
	methodStr = strings.ToLower(method.(string))
	cnetworkPolicyIfc := m["policy_definition"]
	if networkPolicyIfc == nil {
		return errors.New("Expected 'policy_definition' field")
	}
	kubeNetworkPolicy := networkPolicyIfc.(map[string]interface{})
	romanaNetworkPolicy, err := translateNetworkPolicy(kubeNetworkPolicy)
	if err != nil {
		return err
	}
	
	if methodStr == "added" {
		applyNetworkPolicy(networkPolicyActionAdd, romanaNetworkPolicy)
	} else if methodStr == "deleted" {
		applyNetworkPolicy(networkPolicyActioDelete, romanaNetworkPolicy)
	} else if methodStr == "modified" {
		applyNetworkPolicy(networkPolicyActioModify, romanaNetworkPolicy)
	} else {
		return common.NewError("Unexpected method '%s'", methodStr
	}
}

func applyNetworkPolicy(action networkPolicyAction, romanaNetworkPolicy common.Policy) error {
	topoUrl := restClient.GetServiceUrl("topology")
	return nil
}

type kubeListener struct {
	restClient common.RestClient
}

// Run implements the main loop, reconnecting as needed.
func RunListener0(rootURL string, kubeURL string) {
	l := kubeListener{kubeURL: kubeURL, restClient: common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))}
	l.Run()
}	



func (l kubeListener) Run0() {
	for {
		ch := make(chan []byte)
		go listen(ch, l.kubernetesURL)
		for {
			chunk, ok := <-ch
			log.Println(ok)
			if chunk != "" {
				log.Printf("Read chunk %v\n%s\n------------", ok, string(chunk))
				err = processChunk(chunk)
				if err != nil {
					// TODO is there any other way to handle this?
					log.Printf("Error processing chunk %s: %v", string(chunk), err)
				}
			}
			if !ok {
				break
			}
		}
	}
}
/////////////////////////////////////////////////////////////

type networkPolicyAction int

const (
	networkPolicyActionDelete networkPolicyAction = iota
	networkPolicyActionAdd 
	networkPolicyActionModify
)

func RunListener(rootURL string) {
			log.Println("Starting server")
		nsUrl := fmt.Sprintf("%s/%s", config.Api.Url, config.Api.NamespaceUrl)
		nsEvents, err := search.NsWatch(done, nsUrl, config)
		if err != nil {
			log.Fatal("Namespace watcher failed to start", err)
		}

		events := search.Conductor(nsEvents, done, config)
		req := search.Process(events, done, config)
		log.Println("All routines started")
		search.Serve(config, req)
}