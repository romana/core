// Copyright (c) 2015 Pani Networks
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

package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
)

// GetServiceUrl is a convenience function, which, given the root
// service URL and name of desired service, returns the URL of that service.
func (rc *RestClient) GetServiceUrl(rootServiceUrl string, name string) (string, error) {
	log.Printf("Entering GetServiceUrl(%s, %s)", rootServiceUrl, name)
	resp := RootIndexResponse{}
	err := rc.Get(rootServiceUrl, &resp)
	if err != nil {
		return ErrorNoValue, err
	}
	for i := range resp.Services {
		service := resp.Services[i]
		//		log.Println("Checking", service.Name, "against", name, "links:", service.Links)
		if service.Name == name {
			href := service.Links.FindByRel("service")
			log.Println("href:", href)
			if href == "" {
				return ErrorNoValue, errors.New(fmt.Sprintf("Cannot find service %s at %s", name, resp))
			} else {
				// Now for a bit of a trick - this href could be relative...
				// Need to normalize.
				err = rc.NewUrl(href)
				if err != nil {
					return ErrorNoValue, err
				}
				return rc.url.String(), nil
			}
		}
	}
	return ErrorNoValue, errors.New(fmt.Sprintf("Cannot find service %s at %s", name, resp))
}

// execMethod executes the specified method on the provided url (which is interpreted
// as relative or absolute).
func (rc *RestClient) execMethod(method string, url string, data interface{}, result interface{}) error {
	//	log.Printf("RestClient: Going to %s from %s\n", url, rc.url)
	err := rc.NewUrl(url)
	//	log.Printf("RestClient: Set rc.url to %s\n", rc.url)
	if err != nil {
		return err
	}
	var reqBodyReader *bytes.Reader
	var reqBody []byte
	if data != nil {
		reqBody, err = json.Marshal(data)
		if err != nil {
			return err
		}
		reqBodyReader = bytes.NewReader(reqBody)
	} else {
		reqBodyReader = nil
	}

	var body []byte
	if rc.url.Scheme == "http" || rc.url.Scheme == "https" {
		var req *http.Request
		if reqBodyReader == nil {
			req, err = http.NewRequest(method, rc.url.String(), nil)
		} else {
			req, err = http.NewRequest(method, rc.url.String(), reqBodyReader)
		}
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
		log.Printf("Loading file %s, %s", rc.url.String(), rc.url.Path)
		body, err = ioutil.ReadFile(rc.url.Path)

	} else {
		return errors.New(fmt.Sprintf("Unsupported scheme %s", rc.url.Scheme))
	}

	reqBodyStr := ""
	if reqBody != nil {
		reqBodyStr = string(reqBody)
	}
	bodyStr := ""
	if body != nil {
		bodyStr = string(body)
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	log.Printf("\n\t=================================\n\t%s %s\n\t%s\n\t\n\t%s\n\t%s=================================", method, rc.url, reqBodyStr, bodyStr, errStr)

	if err != nil {
		return err
	}

	if result == nil {
		return nil
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return errors.New(fmt.Sprintf("Error %s (%s) when parsing %s", err.Error(), reflect.TypeOf(err), body))
	}
	return nil
}

// Post executes POST method on the specified URL
func (rc *RestClient) Post(url string, data interface{}, result interface{}) error {
	err := rc.execMethod("POST", url, data, result)
	return err
}

// Get executes GET method on the specified URL,
// putting the result into the provided interface
func (rc *RestClient) Get(url string, result interface{}) error {
	return rc.execMethod("GET", url, nil, result)
}

// GetServiceConfig retrieves configuration for a given service from the root service.
func (rc *RestClient) GetServiceConfig(rootServiceUrl string, svc Service) (*ServiceConfig, error) {
	rootIndexResponse := &RootIndexResponse{}
	err := rc.Get(rootServiceUrl, rootIndexResponse)
	if err != nil {
		return nil, err
	}
	config := &ServiceConfig{}
	config.Common.Api = &Api{RootServiceUrl: rootServiceUrl}

	relName := svc.Name() + "-config"

	configUrl := rootIndexResponse.Links.FindByRel(relName)
	if configUrl == "" {
		return nil, errors.New(fmt.Sprintf("Cold not find %s at %s", relName, rootServiceUrl))
	}
	log.Printf("GetServiceConfig(): Found config url %s in %s from %s", configUrl, rootIndexResponse, relName)
	err = rc.Get(configUrl, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
