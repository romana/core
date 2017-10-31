// Copyright (c) 2016-2017 Pani Networks
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
	clog "log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/codegangsta/negroni"

	log "github.com/romana/rlog"
)

const (
	// DefaultTimeout, in milliseconds.
	DefaultTimeout = 500 * time.Millisecond
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
func (s ServiceUtils) AddStatus(requestId string, value interface{}) {
	s.RequestIdToStatus[requestId] = value
	ts := time.Now().Unix()
	s.RequestIdToTimestamp[requestId] = ts
}

// GetStatus gets the status of the request or returns an common.HttpError (404)
// if not found.
func (s ServiceUtils) GetStatus(resourceType string, requestId string) (interface{}, error) {
	val := s.RequestIdToStatus[requestId]
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

// Service is the interface that services implement.
type Service interface {
	Initialize(clientConfig Config) error

	// Returns the routes that this service works with
	Routes() Routes

	// Name returns the name of this service.
	Name() string

	// GetAddr returns the host/port the service is listening on.
	GetAddress() string
}

// initNegroni initializes Negroni with all the middleware and starts it.
func initNegroni(service Service) (*RestServiceInfo, error) {
	var err error
	// Create negroni
	negroni := negroni.New()
	negroni.Use(newPanicRecoveryHandler())

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

	//	authMiddleware, err := NewAuthMiddleware(service, config, client)
	//	if err != nil {
	//		return nil, err
	//	}
	//	negroni.Use(authMiddleware)

	router := newRouter(service.Routes())
	timeoutHandler := http.TimeoutHandler(router, DefaultTimeout, TimeoutMessage)
	negroni.UseHandler(timeoutHandler)

	svcInfo, err := RunNegroni(negroni, service.GetAddress())
	return svcInfo, err
}

// InitializeService initializes the service with the
// provided config and starts it. The channel returned
// allows the caller to wait for a message from the running
// service. Messages are of type ServiceMessage above.
// It can be used for launching service from tests, etc.
func InitializeService(service Service, config Config) (*RestServiceInfo, error) {
	var err error
	err = service.Initialize(config)
	if err != nil {
		return nil, err
	}

	svcInfo, err := initNegroni(service)
	if err != nil {
		return nil, err
	}

	return svcInfo, nil
}

// RunNegroni is a convenience function that runs the negroni stack as a
// provided HTTP server, with the following caveats:
// 1. the Handler field of the provided serverConfig should be nil,
//    because the Handler used will be the n Negroni object.
func RunNegroni(n *negroni.Negroni, addr string) (*RestServiceInfo, error) {
	svr := &http.Server{Addr: addr}
	l := clog.New(os.Stderr, "[negroni] ", 0)
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
	log.Infof("Entering ListenAndServe(%p)", svr)
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
		l = clog.New(os.Stderr, "[negroni] ", 0)
	}
	go func() {
		channel <- Starting
		l.Printf("ListenAndServe(%p): listening on %s (asked for %s)\n", svr, realAddr, svr.Addr)
		err := svr.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
		if err != nil {
			log.Criticalf("RestService: Fatal error %v", err)
			os.Exit(255)
		}
	}()
	return &RestServiceInfo{Address: realAddr, Channel: channel}, nil
}
