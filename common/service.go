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
	//	"errors"
	"fmt"
	"github.com/codegangsta/negroni"
	"log"
	"net"
	"net/http"
	//	"net/url"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
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

	//	// Middlewares returns an array of middleware handlers to add
	//	// in addition to the default set.
	//	Middlewares() []http.Handler
}

// InitializeService initializes the service with the
// provided config and starts it. The channel returned
// allows the calller to wait for a message from the running
// service. Messages are of type ServiceMessage above.
// It can be used for launching service from tests, etc.
func InitializeService(service Service, config ServiceConfig) (*RestServiceInfo, error) {
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

	pubKeyLocation := config.Common.Api.AuthPublic
	config.Common.PublicKey, err = ioutil.ReadFile(pubKeyLocation)
	if err != nil {
		return nil, err
	}
	authMiddleware := AuthMiddleware{PublicKey: config.Common.PublicKey}
	negroni.Use(authMiddleware)

	routes := service.Routes()
	router := newRouter(routes)

	timeoutMillis := config.Common.Api.RestTimeoutMillis
	var dur time.Duration
	var readWriteDur time.Duration
	if timeoutMillis <= 0 {
		timeoutMillis = DefaultRestTimeout
		dur = DefaultRestTimeout * time.Millisecond
		readWriteDur = (DefaultRestTimeout + ReadWriteTimeoutDelta) * time.Millisecond
		log.Printf("%s: Invalid timeout %d, defaulting to %d\n", service.Name(), timeoutMillis, dur)
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
			config := RestClientConfig{TimeoutMillis: timeoutMillis, Retries: retries, Credential: config.Credential}
			client, err := NewRestClient("", config)
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
// arbitrary ports)
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
		l.Fatal(svr.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)}))
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
