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

// This file contains the implementation of HttpClient and related utilities.
package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pborman/uuid"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"time"
)

// Rest Client for the Romana services. Incorporates facilities to deal with
// various REST requests.
type RestClient struct {
	url    *url.URL
	client *http.Client
	config *RestClientConfig
}

// RestClientConfig holds configuration for restful client.
type RestClientConfig struct {
	TimeoutMillis int64
	Retries       int
}

func GetDefaultRestClientConfig() RestClientConfig {
	return RestClientConfig{TimeoutMillis: DefaultRestTimeout, Retries: DefaultRestRetries}
}

// GetRestClientConfig returns a RestClientConfig based on a ServiceConfig
func GetRestClientConfig(config ServiceConfig) RestClientConfig {
	return RestClientConfig{TimeoutMillis: config.Common.Api.RestTimeoutMillis, Retries: config.Common.Api.RestRetries}
}

// NewRestClient creates a new Rest client.
func NewRestClient(url string, config RestClientConfig) (*RestClient, error) {
	rc := &RestClient{client: &http.Client{}, config: &config}
	timeoutMillis := config.TimeoutMillis

	if timeoutMillis <= 0 {
		log.Printf("Invalid timeout %d, defaulting to %d\n", timeoutMillis, DefaultRestTimeout)
		rc.client.Timeout = DefaultRestTimeout * time.Millisecond
	} else {
		timeoutStr := fmt.Sprintf("%dms", timeoutMillis)
		dur, _ := time.ParseDuration(timeoutStr)
		log.Printf("Setting timeout to %v\n", dur)
		rc.client.Timeout = dur
	}
	if config.Retries < 1 {
		log.Printf("Invalid retries %d, defaulting to %d\n", config.Retries, DefaultRestRetries)
		config.Retries = DefaultRestRetries
	}
	if url == "" {
		// If we keep this empty, NewUrl wouldn't work properly when
		// trying to resolve things.
		url = "http://localhost"
	}
	err := rc.NewUrl(url)
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// NewUrl sets the client's new URL (yes, it mutates) to dest.
// If dest is a relative URL then it will be based
// on the previous value of the URL that the RestClient had.
func (rc *RestClient) NewUrl(dest string) error {
	return rc.modifyUrl(dest, nil)
}

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

// modifyUrl sets the client's new URL to dest, possibly updating it with
// new values from the provided queryMod url.Values object.
// If dest is a relative URL then it will be based
// on the previous value of the URL that the RestClient had.
func (rc *RestClient) modifyUrl(dest string, queryMod url.Values) error {
	u, err := url.Parse(dest)
	if err != nil {
		return err
	}

	if rc.url == nil {
		if !u.IsAbs() {
			return errors.New("Expected absolute URL.")
		} else {
			rc.url = u
		}
	} else {
		newUrl := rc.url.ResolveReference(u)
		log.Printf("Getting %s, resolved reference from %s to %s: %s\n", dest, rc.url, u, newUrl)
		rc.url = newUrl
	}

	if queryMod != nil {
		// If the queryMod (url.Values) object is provided, then the
		// query values in the current URL that match keys
		// from that queryMod object are replaced with those from queryMod.
		origUrl := rc.url
		origQuery := origUrl.Query()
		for k, _ := range queryMod {
			origQuery[k] = queryMod[k]
		}
		dest := ""
		for k, v := range origQuery {
			for i := range v {
				if len(dest) > 0 {
					dest += "&"
				}
				dest += url.QueryEscape(k) + "=" + url.QueryEscape(v[i])
			}
		}
		dest = rc.url.Scheme + "://" + rc.url.Host + rc.url.Path + "?" + dest
		rc.url, _ = url.Parse(dest)
		log.Printf("Modified URL %s to %s (%v)\n", origUrl, rc.url, err)
	}

	return nil
}

// execMethod applies the specified method to the provided url (which is interpreted
// as relative or absolute).
func (rc *RestClient) execMethod(method string, dest string, data interface{}, result interface{}) error {
	var queryMod url.Values
	queryMod = nil
	// POST methods may not be idempotent, so for retry capability we will employ the following logic:
	// 1. If the provided structure (data) already has a field "RequestToken", that means the service
	//    is aware of this and is exposing RequestToken as a unique key to enable safe and idempotent
	//    retries. The service would do that if it does not have another way to ensure uniqueness. An
	//    example is IPAM service - a request for an IP address by itself does not necessarily have any
	//    inherent properties that can ensure its uniqueness, unlike a request to, say, add a host (which
	//    has an IP address). IPAM then uses RequestToken for that purpose.
	// 2. If the provided structure does not have that field, and the query does not either, we are going
	//    to generate a uuid and add it to the query as RequestToken=<UUID>. It will then be up to the service
	//    to ensure idempotence or not.
	if method == "POST" {
		var token string
		if data != nil {
			// If the provided struct has the RequestToken field,
			// we don't need to create a query parameter.
			v := reflect.Indirect(reflect.ValueOf(data))
			if !v.FieldByName(RequestTokenQueryParameter).IsValid() {
				queryParam := rc.url.Query().Get(RequestTokenQueryParameter)
				if queryParam == "" {
					queryMod = make(url.Values)
					token = uuid.New()
					log.Printf("Adding token to POST request: %s\n", token)
					queryMod[RequestTokenQueryParameter] = []string{token}
				}
			}
		}
	}
	err := rc.modifyUrl(dest, queryMod)

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
	// We allow also file scheme, for testing purposes.
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

		var resp *http.Response
		for i := 0; i < rc.config.Retries; i++ {
			log.Printf("Try %d for %s", (i + 1), rc.url)
			if i > 0 {
				sleepTime, _ := time.ParseDuration(fmt.Sprintf("%ds", int(math.Pow(2, (float64(i-1))))))
				log.Printf("Sleeping for %v before retrying %d time\n", sleepTime, i)
				time.Sleep(sleepTime)
			}
			resp, err = rc.client.Do(req)
			if err != nil {
				if i == rc.config.Retries-1 {
					return err
				} else {
					log.Println(err)
					continue
				}
			} else {
				// If service unavailable we may still retry...
				if resp.StatusCode != http.StatusServiceUnavailable {
					break
				}
			}
		}
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
	log.Printf("\n\t=================================\n\t%s %s\n\t%s\n\t\n\t%s\n\t%s\n\t=================================", method, rc.url, reqBodyStr, bodyStr, errStr)

	if err != nil {
		return err
	}

	if result == nil {
		return nil
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return errors.New(fmt.Sprintf("Error %s (%T) when parsing %s", err.Error(), err, body))
	}
	return nil
}

// Post applies POST method to the specified URL
func (rc *RestClient) Post(url string, data interface{}, result interface{}) error {
	err := rc.execMethod("POST", url, data, result)
	return err
}

// Get applies GET method to the specified URL,
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
		return nil, errors.New(fmt.Sprintf("Could not find %s at %s", relName, rootServiceUrl))
	}
	log.Printf("GetServiceConfig(): Found config url %s in %s from %s", configUrl, rootIndexResponse, relName)
	err = rc.Get(configUrl, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
