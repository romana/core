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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package common

// This file in package common has functionality related to REST service
// interfaces.

import (
	"errors"
	"fmt"
	"github.com/codegangsta/negroni"
	"log"
	"net"
	"net/http"
	//	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ServiceUtils represents functionality common to various services.
// One example of such functionality is asynchronous processing --
// a service can accept a request for creation of an object and return a
// 202 ACCEPTED, creating an entry that can be queried for status.
type ServiceUtils struct {
	// ResourceIdToStatus is a maps request ID
	// to status. A request ID can be a RequestToken if required,
	// or a resource ID. In general the idea is that this is used
	// in conjunction with RequestToken.
	// See also
	// - Route.UseRequestToken
	// - RestContext.RequestToken
	RequestIdToStatus map[string]interface{}

	// RequestIdToTimestamp maps request ID (for more information
	// on what that is see RequestIdToStatus) to the timestamp
	// of the original request. It will later be used for things
	// such as possible expiration, etc., but for now it's just a
	// placeholder.
	RequestIdToTimestamp map[string]int64
}

// AddStatus adds a status of a request
func (su ServiceUtils) AddStatus(requestId string, value interface{}) {
	su.RequestIdToStatus[requestId] = value
	ts := time.Now().Unix()
	su.RequestIdToTimestamp[requestId] = ts
}

// GetStatus gets the status of the request or returns an common.HttpError (404)
// if not found.
func (su ServiceUtils) GetStatus(resourceType string, requestId string) (interface{}, error) {
	val := su.RequestIdToStatus[requestId]
	if val == nil {
		return nil, NewError404(resourceType, requestId)
	}
	return val, nil
}

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
	return retval

}

//type HostInfo struct {
//	Ip        string `json:"ip"`
//	RomanaIp  string `json:"romana_ip"`
//	AgentPort int    `json:"agentPort"`
//	Name      string `json:"name"`
//}

// HostMessage is a structure representing information
// about the host for the purposes of REST communications
type HostMessage struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	Ip        string `json:"ip"`
	RomanaIp  string `json:"romana_ip"`
	AgentPort int    `json:"agent_port"`
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

	// Name returns the name of this service.
	Name() string
}

// InitializeService initializes the service with the
// provided config and starts it. The channel returned
// allows the calller to wait for a message from the running
// service. Messages are of type ServiceMessage above.
// It can be used for launching service from tests, etc.
func InitializeService(service Service, config ServiceConfig) (*RestServiceInfo, error) {
	log.Printf("Initializing service %s with %v", service.Name(), config.Common.Api)

	routes := service.Routes()

	// Validate hooks
	hooks := config.Common.Api.Hooks
	for i, hook := range hooks {
		if strings.ToLower(hook.When) != "before" && strings.ToLower(hook.When) != "after" {
			return nil, errors.New(fmt.Sprintf("InitializeService(): Invalid value for when: %s", hook.When))
		}
		m := strings.ToUpper(hook.Method)
		if m != "POST" && m != "PUT" && m != "GET" && m != "DELETE" && m != "HEAD" {
			return nil, errors.New(fmt.Sprintf("Invalid method: %s", m))
		}
		found := false
		for j, _ := range routes {
			r := &routes[j]
			if r.Pattern == hook.Pattern && strings.ToUpper(r.Method) == m {
				found = true
				// If you use &hook here instead, guess what happens...
				// you get the last hook attached to all modified routes.
				r.Hook = &hooks[i]
				log.Printf("InitializeService(): [%d] Added hook to run %s %s %s %s", j, hook.Executable, hook.When, r.Method, r.Pattern)
				break
			}
		}

		for i, r := range routes {
			log.Printf("InitializeService(): Modified route[%d]: %s %s %v", i, r.Method, r.Pattern, r.Hook)
		}
		if !found {
			return nil, errors.New(fmt.Sprintf("No route matching pattern %s and method %s found in %v", hook.Pattern, hook.Method, routes))
		}
		finfo, err := os.Stat(hook.Executable)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Problem with specified executable %s: %v", hook.Executable, err))
		}

		if finfo.Mode().Perm()&0111 == 0 {
			return nil, errors.New(fmt.Sprintf("%s is not an executable", hook.Executable))
		}
	}

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

	router := newRouter(routes)

	timeoutMillis := config.Common.Api.RestTimeoutMillis
	var dur time.Duration
	var readWriteDur time.Duration
	if timeoutMillis <= 0 {
		log.Printf("%s: Invalid timeout %d, defaulting to %d\n", service.Name(), timeoutMillis, DefaultRestTimeout)
		timeoutMillis = DefaultRestTimeout
		dur = DefaultRestTimeout * time.Millisecond
		readWriteDur = (DefaultRestTimeout + ReadWriteTimeoutDelta) * time.Millisecond
	} else {
		timeoutStr := fmt.Sprintf("%dms", timeoutMillis)
		dur, _ = time.ParseDuration(timeoutStr)
		timeoutStr = fmt.Sprintf("%dms", timeoutMillis+ReadWriteTimeoutDelta)
		readWriteDur, _ = time.ParseDuration(timeoutStr)
	}

	log.Printf("%s: Creating TimeoutHandler with %v\n", service.Name(), dur)
	timeoutHandler := http.TimeoutHandler(router, dur, TimeoutMessage)
	negroni.UseHandler(timeoutHandler)

	hostPort := config.Common.Api.GetHostPort()
	log.Println("About to start...")
	svcInfo, err := RunNegroni(negroni, hostPort, readWriteDur)

	if err == nil {
		addr := svcInfo.Address
		if addr != hostPort {
			log.Printf("Requested address %s, real %s\n", hostPort, addr)
			idx := strings.LastIndex(addr, ":")
			config.Common.Api.Host = addr[0:idx]
			port, _ := strconv.Atoi(addr[idx+1:])
			port64 := uint64(port)
			config.Common.Api.Port = port64
			// Also register this with root service
			url := fmt.Sprintf("%s/config/%s/port", config.Common.Api.RootServiceUrl, service.Name())
			result := make(map[string]interface{})
			portMsg := PortUpdateMessage{Port: port64}
			retries := config.Common.Api.RestRetries
			if retries <= 0 {
				retries = DefaultRestRetries
			}
			clientConfig := RestClientConfig{TimeoutMillis: timeoutMillis, Retries: retries, TestMode: config.Common.Api.RestTestMode}
			log.Printf("InitializeService() : Initializing Rest client with %v", clientConfig)
			client, err := NewRestClient("", clientConfig)
			if err != nil {
				return svcInfo, err
			}
			err = client.Post(url, portMsg, &result)
		}
	}
	return svcInfo, err
}

// RunNegroni is a convenience function that runs the negroni stack as a
// provided HTTP server, with the following caveats:
// 1. the Handler field of the provided serverConfig should be nil,
//    because the Handler used will be the n Negroni object.
func RunNegroni(n *negroni.Negroni, addr string, timeout time.Duration) (*RestServiceInfo, error) {
	svr := &http.Server{Addr: addr, ReadTimeout: timeout, WriteTimeout: timeout}
	l := log.New(os.Stdout, "[negroni] ", 0)
	svr.Handler = n
	svr.ErrorLog = l
	return ListenAndServe(svr)
}

// tcpKeepAliveListener is taken from http.Server;
// we are copying this in order to keep the same behavior
// as http.Server except for return values of ListenAndServe (see below).
type tcpKeepAliveListener struct {
	*net.TCPListener
}

// This copies the default behavior of http.Server.
// we are copying this in order to keep the same behavior
// as http.Server except for return values of ListenAndServe (see below).
func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

// ListenAndServe is same as http.ListenAndServe except it returns
// the address that will be listened on (which is useful when using
// arbitrary ports).
// See https://github.com/golang/go/blob/master/src/net/http/server.go
func ListenAndServe(svr *http.Server) (*RestServiceInfo, error) {
	if svr.Addr == "" {
		svr.Addr = ":0"
	}
	ln, err := net.Listen("tcp", svr.Addr)
	if err != nil {
		return nil, err
	}
	realAddr := ln.Addr().String()
	channel := make(chan ServiceMessage)
	l := svr.ErrorLog
	if l == nil {
		l = log.New(os.Stdout, "", 0)
	}
	go func() {
		channel <- Starting
		l.Printf("listening on %s (asked for %s) with configuration %v\n", realAddr, svr.Addr, svr)
		err := svr.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
		if err != nil {
			log.Printf("RestService: Fatal error %v", err)
			log.Fatal(err)
		}
	}()
	return &RestServiceInfo{Address: realAddr, Channel: channel}, nil
}

// TODO move here?
//type Tenant struct {
//	Id       uint64 `sql:"AUTO_INCREMENT"`
//	Name     string
//	Seq      uint64
//}
//
//type Segment struct {
//	Id       uint64 `sql:"AUTO_INCREMENT"`
//	Name     string
//	Seq      uint64
//}
