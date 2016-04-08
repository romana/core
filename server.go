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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// SearchRequest associates search request data with channel that will be used
// to fetch response from Processor
type SearchRequest struct {
	Tag  string              `json:"tag"`
	Resp chan SearchResponse `json:",omitempty"`
}

// SearchResponse is a list of kubernetes objects
type SearchResponse []KubeObject

// responseWaiter dispatches search request and waits for search response to arrive.
func responseWaiter(w http.ResponseWriter, request SearchRequest, inbox chan<- SearchRequest, config Config) {
	// Making channel for search responses
	request.Resp = make(chan SearchResponse)
	defer close(request.Resp)

	// Submitting search object to Processor goroutine
	inbox <- request
	if config.Server.Debug {
		log.Println("ResponseWaiter awaiting for answer")
	}

	// Waiting for SearchResponse to arrive
	// TODO handle timeouts here
	response := <-request.Resp

	if config.Server.Debug {
		log.Println("Sending response ", response)
	}

	// Preparing response for sending back to client
	result, err := json.Marshal(response)
	if err != nil {
		log.Println("Failed to marshal search response with json marshaller, that's weird as we expect it to come freshly decoded, ", response)
		panic(err)
	}

	if config.Server.Debug {
		log.Println("Sending response ", string(result))
	}
	fmt.Fprint(w, string(result))
}

// handler to serve search requests from client from this library.
func handler(w http.ResponseWriter, r *http.Request, inbox chan<- SearchRequest, config Config) {
	decoder := json.NewDecoder(r.Body)
	request := SearchRequest{}
	err := decoder.Decode(&request)
	if err != nil {
		panic(err)
	}

	if config.Server.Debug {
		log.Printf("Server passing request %s  to Processor", request)
	}
	responseWaiter(w, request, inbox, config)
}

// Serve responses from caching server.
// Inbox is a channel for submitting SearchRequest's, there is an instance
// of Process goroutine is listening on other side.
func Serve(config Config, inbox chan<- SearchRequest) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, inbox, config)
	})
	log.Fatal(http.ListenAndServe(":"+config.Server.Port, nil))
}
