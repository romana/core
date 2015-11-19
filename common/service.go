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

// This file in package common has functionality related to REST service
// interfaces.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/codegangsta/negroni"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

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
	retval := ""
	for i := range links {
		if links[i].Rel == rel {
			retval = links[i].Href
			break
		}
	}
	log.Printf("FindByRel(): looking for %s in %s: [%s]", rel, links, retval)
	return retval
}

// Response to /
type IndexResponse struct {
	ServiceName string `"json:serviceName"`
	Links       Links
}

// Response from the / path for root only
type RootIndexResponse struct {
	ServiceName string `json:"serviceName"`
	Links       Links
	Services    []ServiceResponse
}

// Service information
type ServiceResponse struct {
	Name  string
	Links Links
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
	Ip        string `json:"ip"`
	RomanaIp  string `json:"romana_ip"`
	Id        string `json:"id"`
	AgentPort int    `json:"agentPort"`
	Name      string `json:"name"`
	Links     Links  `json:"links"`
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

// Client for the Romana services.
type RestClient struct {
	url    *url.URL
	client *http.Client
}

// NewRestClient creates a new Rest client.
func NewRestClient(url string) (*RestClient, error) {
	rc := &RestClient{client: &http.Client{}}
	err := rc.newUrl(url)
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// newUrl sets the client's new URL (yes, it mutates).
// If newUrl is a relative URL then it will be based
// on the previous value of the URL that the RestClient had.
func (rc *RestClient) newUrl(dest string) error {
	url, err := url.Parse(dest)
	if err != nil {
		return err
	}
	if rc.url == nil {
		if !url.IsAbs() {
			return errors.New("Expected absolute URL.")
		} else {
			rc.url = url
		}
	} else {
		newUrl := rc.url.ResolveReference(url)
		//		log.Printf("newUrl(): Replacing %s with %s", rc.url, newUrl)
		rc.url = newUrl
	}
	return nil
}

// GetServiceUrl is a convenience function, which, given the root
// service URL and name of desired service, returns the URL of that service.
func GetServiceUrl(rootServiceUrl string, name string) (string, error) {
	log.Printf("Entering GetServiceUrl(%s, %s)", rootServiceUrl, name)
	client, err := NewRestClient(rootServiceUrl)
	if err != nil {
		return "", err
	}
	resp := RootIndexResponse{}
	err = client.Get("", &resp)
	if err != nil {
		return "", err
	}
	for i := range resp.Services {
		service := resp.Services[i]
		if service.Name == name {
			href := service.Links.FindByRel("service")
			if href == "" {
				return "", errors.New(fmt.Sprintf("Cannot find service %s at %s", name, resp))
			} else {
				// Now for a bit of a trick - this href could be relative...
				// Need to normalize.
				err = client.newUrl(href)
				if err != nil {
					return "", err
				}
				return client.url.String(), nil
			}
		}
	}

	return "", errors.New(fmt.Sprintf("Cannot find service %s at %s", name, resp))

}

// execMethod executes the specified method on the provided url (which is interpreted
// as relative or absolute).
func (rc *RestClient) execMethod(method string, url string, data interface{}, result interface{}) error {
	log.Printf("Going to %s from %s", url, rc.url)
	err := rc.newUrl(url)
	if err != nil {
		return err
	}
	var reqBodyReader *bytes.Reader

	if data != nil {
		reqBody, err := json.Marshal(data)
		if err != nil {
			return err
		}
		reqBodyReader = bytes.NewReader(reqBody)
	} else {
		reqBodyReader = nil
	}

	var body []byte
	if rc.url.Scheme == "http" || rc.url.Scheme == "https" {
		req, err := http.NewRequest(method, rc.url.String(), reqBodyReader)
		if reqBodyReader != nil {
			req.Header.Set("content-type", "application/json")
		}
		if err != nil {
			return err
		}

		req.Header.Set("accept", "application/json")
		resp, err := rc.client.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()
		body, err = ioutil.ReadAll(resp.Body)
	} else if rc.url.Scheme == "file" {
		log.Printf("Loading file ", rc.url.String(), rc.url.Path)
		body, err = ioutil.ReadFile(rc.url.Path)
	} else {
		return errors.New(fmt.Sprintf("Unsupported scheme %s", rc.url.Scheme))
	}

	if err != nil {
		return err
	}

	if result == nil {
		return nil
	}

	err = json.Unmarshal(body, &result)
	return err
}

// Post executes POST method on the specified URL
func (rc *RestClient) Post(url string, data interface{}, result interface{}) error {
	return rc.execMethod("POST", url, data, result)
}

// Get executes GET method on the specified URL,
// putting the result into the provided interface
func (rc RestClient) Get(url string, result interface{}) error {
	return rc.execMethod("GET", url, nil, result)
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
	log.Printf("Listening on %s" + hostPort)
	return channel, nil
}

// GetServiceConfig is to get configuration from a root service
func GetServiceConfig(rootServiceUrl string, name string) (*ServiceConfig, error) {
	client, err := NewRestClient(rootServiceUrl)
	if err != nil {
		return nil, err
	}

	rootIndexResponse := &RootIndexResponse{}
	err = client.Get("", rootIndexResponse)
	if err != nil {
		return nil, err
	}
	config := &ServiceConfig{}
	config.Common.Api.RootServiceUrl = rootServiceUrl
	relName := name + "-config"

	configUrl := rootIndexResponse.Links.FindByRel(relName)
	if configUrl == "" {
		return nil, errors.New(fmt.Sprintf("Cold not find %s at %s", relName, rootServiceUrl))
	}
	log.Printf("GetServiceConfig(): Found config url %s in %s from %", configUrl, rootIndexResponse, relName)
	err = client.Get(configUrl, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
