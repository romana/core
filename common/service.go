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
	"flag"
	"fmt"
	"github.com/codegangsta/negroni"
	"github.com/golang/glog"
	config "github.com/spf13/viper"
	"io/ioutil"
	clog "log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/romana/rlog"
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

// CreateFindRoutes creates Routes for a find functionality given the
// provided entities. Four routes are created:
// 1. /findOne/<entityName>s, which will return a single structure (or
// an error if more than one entry is found,
// 2. /findFirst/<entityName>s, which will return the first entity (in order
// of their creation).
// 3. /findLast/<entityName>s -- similar to above.
// 4. /findAll/<entityName>s
// Routes will return a 404 if no entries found.
// Here "entities" *must* be a pointer to an array
// of entities to find (for example, it has to be &[]Tenant{}, not Tenant{}),
// which will then create /findOne/tenants (returning Tenant structure}
// and /findAll/tenants (returning []Tenant array) routes.
func CreateFindRoutes(entities interface{}, store Store) Routes {
	entityName := reflect.TypeOf(entities).Elem().Elem().String()
	entityNameElements := strings.Split(entityName, ".")
	if len(entityNameElements) == 2 {
		entityName = entityNameElements[1]
	}
	entityName = strings.ToLower(entityName)
	pathSuffix := "/" + entityName + "s"

	routes := Routes{
		Route{
			Method:  "GET",
			Pattern: "/" + FindAll + pathSuffix,
			Handler: func(input interface{}, ctx RestContext) (interface{}, error) {
				return store.Find(ctx.QueryVariables, entities, FindAll)
			},
		},
		Route{
			Method:  "GET",
			Pattern: "/" + FindExactlyOne + pathSuffix,
			Handler: func(input interface{}, ctx RestContext) (interface{}, error) {
				return store.Find(ctx.QueryVariables, entities, FindExactlyOne)
			},
		},
		Route{
			Method:  "GET",
			Pattern: "/" + FindFirst + pathSuffix,
			Handler: func(input interface{}, ctx RestContext) (interface{}, error) {
				return store.Find(ctx.QueryVariables, entities, FindFirst)
			},
		},
		Route{
			Method:  "GET",
			Pattern: "/" + FindLast + pathSuffix,
			Handler: func(input interface{}, ctx RestContext) (interface{}, error) {
				return store.Find(ctx.QueryVariables, entities, FindLast)
			},
		},
	}
	return routes
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

// Service is the interface that microservices implement.
type Service interface {
	// SetConfig sets the configuration, validating it if needed
	// and returning an error if not valid.
	SetConfig(config ServiceConfig) error

	// Initializes the service (mostly for error reporting, could be a no-op)
	Initialize(client *RestClient) error

	// Returns the routes that this service works with
	Routes() Routes

	// Name returns the name of this service.
	Name() string

	CreateSchema(overwrite bool) error
}

// setupHooks sets up before and after hooks for each service
func setupHooks(routes Routes, hooks []Hook) error {
	for i, hook := range hooks {
		if strings.ToLower(hook.When) != "before" && strings.ToLower(hook.When) != "after" {
			return errors.New(fmt.Sprintf("InitializeService(): Invalid value for when: %s", hook.When))
		}
		m := strings.ToUpper(hook.Method)
		if m != "POST" && m != "PUT" && m != "GET" && m != "DELETE" && m != "HEAD" {
			return errors.New(fmt.Sprintf("Invalid method: %s", m))
		}
		found := false
		for j, _ := range routes {
			r := &routes[j]
			if r.Pattern == hook.Pattern && strings.ToUpper(r.Method) == m {
				found = true
				r.Hook = &hooks[i]
				log.Infof("InitializeService(): [%d] Added hook to run %s %s %s %s", j, hook.Executable, hook.When, r.Method, r.Pattern)
				break
			}
		}

		for i, r := range routes {
			log.Infof("InitializeService(): Modified route[%d]: %s %s %v", i, r.Method, r.Pattern, r.Hook)
		}
		if !found {
			return errors.New(fmt.Sprintf("No route matching pattern %s and method %s found in %v", hook.Pattern, hook.Method, routes))
		}
		finfo, err := os.Stat(hook.Executable)
		if err != nil {
			return errors.New(fmt.Sprintf("Problem with specified executable %s: %v", hook.Executable, err))
		}

		if finfo.Mode().Perm()&0111 == 0 {
			return errors.New(fmt.Sprintf("%s is not an executable", hook.Executable))
		}
	}
	return nil

}

// initNegroni initializes Negroni with all the middleware and starts it.
func initNegroni(routes Routes, config ServiceConfig) (*RestServiceInfo, error) {
	var err error
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
	if pubKeyLocation != "" {
		log.Infof("Reading public key from %s", pubKeyLocation)
		config.Common.PublicKey, err = ioutil.ReadFile(pubKeyLocation)
	}
	if err != nil {
		return nil, err
	}
	// We use the public key of root server to check the token.
	authMiddleware := AuthMiddleware{PublicKey: config.Common.PublicKey}
	negroni.Use(authMiddleware)

	timeoutMillis := getTimeoutMillis(config.Common)
	var dur time.Duration
	var readWriteDur time.Duration
	timeoutStr := fmt.Sprintf("%dms", timeoutMillis)
	dur, _ = time.ParseDuration(timeoutStr)
	timeoutStr = fmt.Sprintf("%dms", timeoutMillis+ReadWriteTimeoutDelta)
	readWriteDur, _ = time.ParseDuration(timeoutStr)

	router := newRouter(routes)
	timeoutHandler := http.TimeoutHandler(router, dur, TimeoutMessage)
	negroni.UseHandler(timeoutHandler)

	hostPort := config.Common.Api.GetHostPort()
	svcInfo, err := RunNegroni(negroni, hostPort, readWriteDur)
	return svcInfo, err
}

func getTimeoutMillis(config CommonConfig) int64 {
	timeoutMillis := config.Api.RestTimeoutMillis
	if timeoutMillis <= 0 {
		timeoutMillis = DefaultRestTimeout
	}
	return timeoutMillis
}

// InitializeService initializes the service with the
// provided config and starts it. The channel returned
// allows the caller to wait for a message from the running
// service. Messages are of type ServiceMessage above.
// It can be used for launching service from tests, etc.
func InitializeService(service Service, config ServiceConfig, credential *Credential) (*RestServiceInfo, error) {
	log.Infof("Initializing service %s with %v", service.Name(), config.Common.Api)
	var err error
	routes := service.Routes()
	hooks := config.Common.Api.Hooks
	err = setupHooks(routes, hooks)
	if err != nil {
		return nil, err
	}

	err = service.SetConfig(config)
	if err != nil {
		return nil, err
	}

	// Create Rest client and initialize service with it.
	retries := config.Common.Api.RestRetries
	if retries <= 0 {
		retries = DefaultRestRetries
	}
	clientConfig := RestClientConfig{TimeoutMillis: getTimeoutMillis(config.Common),
		Retries:    retries,
		RootURL:    config.Common.Api.RootServiceUrl,
		TestMode:   config.Common.Api.RestTestMode,
		Credential: credential,
	}
	client, err := NewRestClient(clientConfig)
	if err != nil {
		return nil, err
	}
	service.Initialize(client)

	svcInfo, err := initNegroni(routes, config)
	if err != nil {
		return nil, err
	}

	requestedAddr := config.Common.Api.GetHostPort()
	realAddr := svcInfo.Address
	if realAddr != requestedAddr {
		idx := strings.LastIndex(realAddr, ":")
		config.Common.Api.Host = realAddr[0:idx]
		port, _ := strconv.Atoi(realAddr[idx+1:])
		port64 := uint64(port)
		config.Common.Api.Port = port64
		// Also register this with root service if we are not root ourselves.
		if service.Name() != ServiceRoot {
			result := make(map[string]interface{})
			portMsg := PortUpdateMessage{Port: port64}
			url := fmt.Sprintf("%s/config/%s/port", config.Common.Api.RootServiceUrl, service.Name())
			log.Infof("For service %s, requested address %s, real %s, registering at %s\n", service.Name(), requestedAddr, realAddr, url)
			err = client.Post(url, portMsg, &result)
			if err != nil {
				log.Infof("Error attempting to register service %s with root: %+v", service.Name(), err)
			} else {
				log.Infof("Registered service %s with root: %+v: %+v", service.Name(), portMsg, result)
			}
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
		l.Printf("ListenAndServe(%p): listening on %s (asked for %s) with configuration %v, handler %v\n", svr, realAddr, svr.Addr, svr, svr.Handler)
		err := svr.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
		if err != nil {
			log.Criticalf("RestService: Fatal error %v", err)
			os.Exit(255)
		}
	}()
	return &RestServiceInfo{Address: realAddr, Channel: channel}, nil
}

// CliState represents the state needed for starting of various
// services. This is here to avoid copy-pasting common command-line
// argument information, configuration, credentials, etc.
type CliState struct {
	CreateSchema    *bool
	OverwriteSchema *bool
	RootURL         *string
	version         *bool
	ConfigFile      *string
	credential      *Credential
	flagSet         *flag.FlagSet
}

// NewCliState creates a new CliState with initial fields
func NewCliState() *CliState {
	cs := &CliState{}
	cs.flagSet = flag.NewFlagSet("RomanaService", flag.ContinueOnError)
	cs.CreateSchema = cs.flagSet.Bool("createSchema", false, "Create schema")
	cs.OverwriteSchema = cs.flagSet.Bool("overwriteSchema", false, "Overwrite schema")
	cs.RootURL = cs.flagSet.String("RootURL", "", "URL to root service URL")
	cs.version = cs.flagSet.Bool("version", false, "Build Information.")
	// This config file is not the same as one in Romana CLI for now... It is
	// the config file for Root service.
	// TODO: We should perhaps differentiate them somehow...
	cs.ConfigFile = cs.flagSet.String("c", "", "config file")
	cs.credential = NewCredential(cs.flagSet)
	return cs
}

// Init calls flag.Parse() and, for now, sets up the
// credentials.
func (cs *CliState) Init() error {
	cs.flagSet.Parse(os.Args[1:])
	config.SetConfigName(".romana") // name of config file (without extension)
	config.SetConfigType("yaml")
	config.AddConfigPath("$HOME") // adding home directory as first search path
	config.AutomaticEnv()         // read in environment variables that match

	// If a config file is found, read it in.
	err := config.ReadInConfig()
	if err != nil {
		switch err := err.(type) {
		case config.ConfigFileNotFoundError:
			// For now do nothing
		case *os.PathError:
			if err.Error() != "open : no such file or directory" {
				return err
			}
		default:
			return err
		}
	}
	glog.Infof("Using config file: %s", config.ConfigFileUsed())
	err = cs.credential.Initialize()
	return err
}

// SimpleOverwriteSchema is intended to be used from tests, it provides
// a shortcut for the overwriteSchema functionality.
func SimpleOverwriteSchema(svc Service, rootURL string) error {
	cs := NewCliState()
	overwriteSchema := true
	cs.RootURL = &rootURL
	cs.OverwriteSchema = &overwriteSchema
	_, err := cs.StartService(svc)
	return err
}

func SimpleStartService(svc Service, rootURL string) (*RestServiceInfo, error) {
	cs := NewCliState()
	cs.RootURL = &rootURL
	rsi, err := cs.StartService(svc)
	return rsi, err
}

// Init calls Init() and starts the provided service (or,
// does what is required by command-line arguments, such as printing
// usage info or version).
func (c *CliState) StartService(svc Service) (*RestServiceInfo, error) {
	err := c.Init()
	if err != nil {
		return nil, err
	}

	if *c.version {
		fmt.Println(BuildInfo())
		return nil, nil
	}

	if svc.Name() == "root" {
		// Root is special, we do not launch it here. Root's main
		// will do it.
		return nil, nil
	} else {
		if *c.RootURL == "" {
			fmt.Println("Must specify RootURL.")
			return nil, nil
		}
	}

	clientConfig := GetDefaultRestClientConfig(*c.RootURL)
	clientConfig.Credential = c.credential
	client, err := NewRestClient(clientConfig)
	if err != nil {
		return nil, err
	}

	config, err := client.GetServiceConfig(svc.Name())
	if err != nil {
		return nil, err
	}

	if *c.CreateSchema || *c.OverwriteSchema {
		svc.SetConfig(*config)
		err := svc.CreateSchema(*c.OverwriteSchema)
		if err != nil {
			return nil, err
		}
		fmt.Println("Schema created.")
		return nil, nil
	}

	return InitializeService(svc, *config, c.credential)
}
