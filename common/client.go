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

// Contains the implementation of HttpClient and related utilities.

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
	url            *url.URL
	client         *http.Client
	token          string
	config         *RestClientConfig
	lastStatusCode int
}

// RestClientConfig holds configuration for restful client.
type RestClientConfig struct {
	TimeoutMillis int64
	Retries       int
	Credential    *Credential
	TestMode      bool
	RootURL       string
}

// GetDefaultRestClientConfig gets a RestClientConfig with specified rootURL
// and other values set to their defaults: DefaultRestTimeout, DefaultRestRetries.
func GetDefaultRestClientConfig(rootURL string) RestClientConfig {
	return RestClientConfig{TimeoutMillis: DefaultRestTimeout, Retries: DefaultRestRetries, RootURL: rootURL}
}

// GetRestClientConfig returns a RestClientConfig based on a ServiceConfig. That is,
// the information provided in the service configuration is used for the client
// configuration.
func GetRestClientConfig(config ServiceConfig) RestClientConfig {
	return RestClientConfig{TimeoutMillis: config.Common.Api.RestTimeoutMillis, Retries: config.Common.Api.RestRetries, RootURL: config.Common.Api.RootServiceUrl}
}

// NewRestClient creates a new Romana REST client. It provides convenience
// methods to make REST calls. When configured with a root URL pointing
// to Romana root service, it provides some common functionality useful
// for Romana services (such as ListHosts, GetServiceConfig, etc.)
// If the root URL does not point to the Romana service, the generic REST operations
// still work, but Romana-specific functionality does not.
func NewRestClient(config RestClientConfig) (*RestClient, error) {
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
	var myUrl string
	if config.RootURL == "" {
		// Default to some URL. This client would not be able to be used
		// for Romana-related service convenience methods, just as a generic
		// REST client.
		// If we keep this empty, NewUrl wouldn't work properly when
		// trying to resolve things.
		myUrl = "http://localhost"
	} else {
		u, err := url.Parse(config.RootURL)
		if err != nil {
			return nil, err
		}
		if !u.IsAbs() {
			return nil, NewError("Expected absolute URL for root, received %s", config.RootURL)
		}
		myUrl = config.RootURL
	}
	err := rc.NewUrl(myUrl)
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

// GetStatusCode returns status code of last executed request.
// As stated above, it is not recommended to share RestClient between
// goroutines. 0 is returned if no previous requests have been yet
// made, or if the most recent request resulted in some error that
// was not a 4xx or 5xx HTTP error.
func (rc *RestClient) GetStatusCode() int {
	return rc.lastStatusCode
}

// ListHost queries the Topology service in order to return a list of currently
// configured hosts in a Romana cluster.
func (rc *RestClient) ListHosts() ([]HostMessage, error) {
	// Save the current state of things, so we can restore after call to root.
	savedUrl := rc.url
	// Restore this after we're done so we don't lose this
	defer func() {
		rc.url = savedUrl
	}()

	topoUrl, err := rc.GetServiceUrl("topology")
	if err != nil {
		return nil, err
	}
	topIndex := IndexResponse{}
	err = rc.Get(topoUrl, &topIndex)
	if err != nil {
		return nil, err
	}
	hostsRelURL := topIndex.Links.FindByRel("host-list")

	var hostList []HostMessage
	err = rc.Get(hostsRelURL, &hostList)
	return hostList, err
}

// GetServiceUrl is a convenience function, which, given the root
// service URL and name of desired service, returns the URL of that service.
func (rc *RestClient) GetServiceUrl(name string) (string, error) {
	log.Printf("Entering GetServiceUrl(%s, %s)", rc.config.RootURL, name)
	// Save the current state of things, so we can restore after call to root.
	savedUrl := rc.url
	// Restore this after we're done so we don't lose this
	defer func() {
		rc.url = savedUrl
	}()
	resp := RootIndexResponse{}

	err := rc.Get(rc.config.RootURL, &resp)
	if err != nil {
		return ErrorNoValue, err
	}
	for i := range resp.Services {
		service := resp.Services[i]
		//		log.Println("Checking", service.Name, "against", name, "links:", service.Links)
		if service.Name == name {
			href := service.Links.FindByRel("service")
			log.Println("href:", href)
			if href != "" {
				// Now for a bit of a trick - this href could be relative...
				// Need to normalize.
				err = rc.NewUrl(href)
				if err != nil {
					return ErrorNoValue, err
				}
				return rc.url.String(), nil
			}
			return ErrorNoValue, errors.New(fmt.Sprintf("Cannot find service %s at %s", name, resp))
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
		}
		rc.url = u
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
		for k := range queryMod {
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
func (rc *RestClient) execMethod(method string, dest string, data interface{}, result interface{}) error {
	// TODO check if token expired, if yes, reauthenticate... But this needs
	// more state here (knowledge of Root service by Rest client...)
	rc.lastStatusCode = 0
	var queryMod url.Values
	queryMod = nil
	if method == "POST" && rc.config != nil && !rc.config.TestMode {
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

	log.Printf("Scheme is %s, method is %s, test mode: %t", rc.url.Scheme, method, rc.config.TestMode)
	if rc.url.Scheme == "file" && method == "POST" && rc.config.TestMode {
		log.Printf("Attempt to POST to a file URL %s, in test mode will just return OK", rc.url)
		return nil
	}

	var reqBodyReader *bytes.Reader
	var reqBody []byte
	if data != nil {
		reqBody, err = json.Marshal(data)
		log.Printf("RestClient.execMethod(): Marshaled %T %v to %s", data, data, string(reqBody))
		if err != nil {
			return err
		}
		reqBodyReader = bytes.NewReader(reqBody)
	} else {
		reqBodyReader = nil
	}

	var body []byte
	// We allow also file scheme, for testing purposes.
	var resp *http.Response
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
		if rc.token != "" {
			req.Header.Set("authorization", rc.token)
		}
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
				}
				log.Println(err)
				continue
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
		resp = &http.Response{}
		resp.StatusCode = http.StatusOK
		log.Printf("RestClient: Loading file %s, %s", rc.url.String(), rc.url.Path)
		body, err = ioutil.ReadFile(rc.url.Path)
		if err != nil {
			log.Printf("RestClient: Error loading file %s: %v", rc.url.Path, err)
			return err
		}
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
		errStr = fmt.Sprintf("ERROR: <%v>", err)
	}
	log.Printf("\n\t=================================\n\t%s %s: %d\n\t%s\n\n\t%s\n\t%s\n\t=================================", method, rc.url, resp.StatusCode, reqBodyStr, bodyStr, errStr)

	if err != nil {
		return err
	}

	var unmarshalBodyErr error

	//	TODO deal properly with 3xx
	//	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
	//		log.Printf("3xx: %d %v", resp.StatusCode, resp.Header)
	//	}
	//
	if result != nil {
		if body != nil {
			unmarshalBodyErr = json.Unmarshal(body, &result)
		}
	}

	rc.lastStatusCode = resp.StatusCode

	if resp.StatusCode >= 400 {
		// The body should be an HTTP error
		httpError := &HttpError{}
		unmarshalBodyErr = json.Unmarshal(body, httpError)
		httpError.StatusCode = resp.StatusCode
		if unmarshalBodyErr == nil {
			if resp.StatusCode == http.StatusConflict {
				// In case of conflict, we actually expect the object that caused
				// conflict to appear in details... So we want to marshal this back to JSON
				// and unmarshal into what we know should be...
				j, err := json.Marshal(httpError.Details)
				if err != nil {
					httpError.Details = errors.New(fmt.Sprintf("Error parsing '%v': %s", httpError.Details, err))
					return httpError
				}
				err = json.Unmarshal(j, &result)
				if err != nil {
					httpError.Details = errors.New(fmt.Sprintf("Error parsing '%s': %s", j, err))
					return httpError
				}
				httpError.Details = result
			}
			return *httpError
		}
		// Error unmarshaling body...
		httpError.Details = errors.New(fmt.Sprintf("Error parsing '%v': %s", bodyStr, err))
		return *httpError
	}
	// OK response...
	if unmarshalBodyErr != nil {
		return errors.New(fmt.Sprintf("Error %s (%T) when parsing %s", unmarshalBodyErr.Error(), err, body))
	}
	return nil
}

// Post applies POST method to the specified URL,
// putting the result into the provided interface
func (rc *RestClient) Post(url string, data interface{}, result interface{}) error {
	err := rc.execMethod("POST", url, data, result)
	return err
}

// Delete applies DELETE method to the specified URL,
// putting the result into the provided interface
func (rc *RestClient) Delete(url string, data interface{}, result interface{}) error {
	err := rc.execMethod("DELETE", url, data, result)
	return err
}

// Put applies PUT method to the specified URL,
// putting the result into the provided interface
func (rc *RestClient) Put(url string, data interface{}, result interface{}) error {
	err := rc.execMethod("PUT", url, data, result)
	return err
}

// Get applies GET method to the specified URL,
// putting the result into the provided interface
func (rc *RestClient) Get(url string, result interface{}) error {
	return rc.execMethod("GET", url, nil, result)
}

// GetServiceConfig retrieves configuration
// for the given service from the root service.
func (rc *RestClient) GetServiceConfig(name string) (*ServiceConfig, error) {
	rootIndexResponse := &RootIndexResponse{}
	if rc.config.RootURL == "" {
		return nil, errors.New("RootURL not set")
	}
	err := rc.Get(rc.config.RootURL, rootIndexResponse)
	if err != nil {
		return nil, err
	}

	if rc.config.Credential != nil && rc.config.Credential.Type != CredentialNone {
		// First things first - authenticate
		authUrl := rootIndexResponse.Links.FindByRel("auth")
		log.Printf("Authenticating to %s", authUrl)
		tokenMsg := &TokenMessage{}
		err = rc.Post(authUrl, rc.config.Credential, tokenMsg)
		if err != nil {
			return nil, err
		}
		rc.token = tokenMsg.Token
	}

	config := &ServiceConfig{}
	config.Common.Api = &Api{RootServiceUrl: rc.config.RootURL}
	relName := name + "-config"
	configUrl := rootIndexResponse.Links.FindByRel(relName)
	if configUrl == "" {
		return nil, errors.New(fmt.Sprintf("Could not find %s at %s", relName, rc.config.RootURL))
	}
	log.Printf("GetServiceConfig(): Found config url %s in %s from %s", configUrl, rootIndexResponse, relName)
	err = rc.Get(configUrl, config)
	if err != nil {
		return nil, err
	}
	// Save the credential from the client in the resulting service config --
	// if the resulting config is to be used in InitializeService(), it's useful;
	// otherwise, it will be ignored.
	config.Common.Credential = rc.config.Credential
	log.Printf("Saved from %v to %v", rc.config.Credential, config.Common.Credential)
	return config, nil
}
