// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/codegangsta/negroni"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

type Links []LinkResponse

// FindByRel finds the path (href) for a link based on its
// rel value. This is because in the REST message links are
// organized as an array of structures containing href and rel,
// but, of course, in actual usage it is easier to be used as a
// map.
func (links Links) FindByRel(rel string) string {
	for i := range links {
		if links[i].Rel == rel {
			return links[i].Href
		}
	}

	return ""
}

// Response to /
type IndexResponse struct {
	ServiceName string `"json:serviceName"`
	Links       Links
}

// Structure representing the commonly occurring
// {
//          "href" : "https://<own-addr>",
//        "rel"  : "self"
//  }
// part of the response
type LinkResponse struct {
	Href string
	Rel  string
}

// HostMessage is a structure representing information
// about the host for the purposes of REST communications
type HostMessage struct {
	Ip        string                `json:"ip"`
	Id        string                `json:"id"`
	AgentPort int                   `json:"agentPort"`
	Name      string                `json:"name"`
	Links     []LinkResponse `json:"links"`
	//    Tor string       `json:"tor"`
}

// Service is the interface that microservices implement.
type Service interface {
	// SetConfig sets the configuration, validating it if needed
	// and returning an error if not valid.
	SetConfig(config ServiceConfig) error

	// Initializes the service (mostly for error reporting, could be a no-op)
	Initialize() error

	// Returns the routes that this service works with
	Routes() Routes
}

type RestClient struct {
	URL string
}

// Get executes POST method on the specified URL
func (rc RestClient) Post(url string, data interface{}, result interface{}) error {
	client := &http.Client{}
	reqBody, err := json.Marshal(data)
	if err != nil {
		return err
	}
	reqBodyReader := bytes.NewReader(reqBody)
	req, err := http.NewRequest("POST", rc.URL+url, reqBodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if result == nil {
		return nil
	}

	err = json.Unmarshal(respBody, &result)
	return err
}

// Get executes GET method on the specified URL,
// putting the result into the provided interface
func (rc RestClient) Get(url string, result interface{}) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", rc.URL+url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if result == nil {
		return nil
	}

	err = json.Unmarshal(body, &result)
	return err
}

type ServiceMessage string

const (
	Starting ServiceMessage = "Starting."
)

// InitializeService initializes the service with the
// provided config and starts it. The channel returned
// allows the calller to wait for a message from the running
// service. Messages are of type ServiceMessage above.
// It can be used for launching service from tests, etc.
func InitializeService(service Service, config ServiceConfig) (chan ServiceMessage, error) {
	channel := make(chan ServiceMessage)
	err := service.SetConfig(config)
	if err != nil {
		return nil, err
	}
	err = service.Initialize()
	if err != nil {
		return nil, err
	}
	// Create negroni
	negroni := negroni.New()

	// Add authentication middleware
	negroni.Use(NewAuth())

	// Add content-negotiation middleware.
	// This is an example of using a middleware.
	// This will modify the response header to the
	// negotiated content type, and can then be used as
	// ct := w.Header().Get("Content-Type")
	// where w is http.ResponseWriter
	negroni.Use(NewNegotiator())

	// Unmarshal data from the content-type format
	// into a map
	negroni.Use(NewUnmarshaller())

	routes := service.Routes()
	router := newRouter(routes)
	negroni.UseHandler(router)

	portStr := strconv.FormatUint(config.Common.Api.Port, 10)
	hostPort := strings.Join([]string{config.Common.Api.Host, portStr}, ":")
	go func() {
		channel <- Starting
		negroni.Run(hostPort)
	}()
	fmt.Println("Listening on " + hostPort)
	return channel, nil
}

// GetServiceConfig is to get configuration from a root service
func GetServiceConfig(rootServiceUrl string, name string) (*ServiceConfig, error) {
	client := RestClient{rootServiceUrl}
	config := &ServiceConfig{}
	path := "/config/" + name
	fmt.Println("Calling", rootServiceUrl+path)
	err := client.Get(path, config)
	if err != nil {
		return nil, err
	}
	fmt.Println("Got", config)
	return config, nil
}
