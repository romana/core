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

// This file contains things related to the REST framework.
package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/K-Phoen/negotiation"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/url"
	"reflect"
	"strings"
	//	"log"
	"net/http"
)

// Context of the REST request other than the body data
// that has been unmarshaled.
type RestContext struct {
	// Path variables as described in https://godoc.org/code.google.com/p/gorilla/mux
	PathVariables map[string]string
	// QueryVariables stores key-value-list map of query variables, see url.Values
	// for more details.
	QueryVariables url.Values
}

// RestHandler specifies type of a function that each Route provides.
// It takes (for now) an interface as input, and returns any
// interface. The middleware provided in this file takes care
// of unmarshalling the data from the wire to the input object
// (the type of the object created will be determined by the
// type of the instance provided in Consumes field of Route type, below),
// and of marshalling the returned object to the wire (the type of
// which is determined by type of the instance provided in Produces
// field of Route type, below).
type RestHandler func(input interface{}, context RestContext) (interface{}, error)

// UnwrappedRestHandlerInput is used to pass in
// http.Request and http.ResponseWriter, should some
// service like unfettered access directly to them. In
// such a case, the service's RestHandler's input will be of this type;
// and the return value will be ignored.
type UnwrappedRestHandlerInput struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request
}

// A factory function, which should return a pointer to
// an instance into which we will unmarshal wire data.
type MakeMessage func() interface{}

// Route determines an action taken on a URL pattern/HTTP method.
// Each service can define a route
// See routes.go and handlers.go in root package for a demonstration
// of use
type Route struct {
	// REST method
	Method string

	// Pattern (see http://www.gorillatoolkit.org/pkg/mux)
	Pattern string

	// Handler (see documentation above)
	Handler RestHandler

	// This should return a POINTER to an instance which
	// this route expects as an input.
	MakeMessage MakeMessage
}

// Each service defines routes
type Routes []Route

// RomanaHandler interface to comply with http.Handler
type RomanaHandler struct {
	doServeHTTP func(writer http.ResponseWriter, request *http.Request)
}

// ServeHTTP is required by
// https://golang.org/pkg/net/http/#Handler
func (romanaHandler RomanaHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	romanaHandler.doServeHTTP(writer, request)
}

// For comparing to the type of Consumes field of Route struct.
var requestType = reflect.TypeOf(http.Request{})

// For comparing to the type of string.
var stringType = reflect.TypeOf("")

// wrapHandler wraps the RestHandler function, which deals
// with application logic into an instance of http.HandlerFunc
// which deals with raw HTTP request and response. The wrapper
// is intended to transparently deal with converting data to/from
// the wire format into internal representations.
func wrapHandler(restHandler RestHandler, makeMessage MakeMessage) http.Handler {
	if makeMessage != nil && reflect.TypeOf(makeMessage()) == requestType {
		// This would mean the handler actually wants access to raw request/response
		// Fine, then...
		httpHandler := func(writer http.ResponseWriter, request *http.Request) {
			err := request.ParseForm()
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				writer.Write([]byte(err.Error()))
				return
			}
			restContext := RestContext{PathVariables: mux.Vars(request), QueryVariables: request.Form}

			respReq := UnwrappedRestHandlerInput{writer, request}
			restHandler(respReq, restContext)
		}
		return RomanaHandler{httpHandler}
	} else {
		httpHandler := func(writer http.ResponseWriter, request *http.Request) {
			var inData interface{}
			if makeMessage == nil {
				inData = nil
			} else {
				inData = makeMessage()
			}
			var err error
			if inData != nil {
				log.Printf("httpHandler: inData addr: %d\n", &inData)
				ct := request.Header.Get("content-type")
				buf, err := ioutil.ReadAll(request.Body)
				log.Printf("Read %s\n", string(buf))
				if err != nil {
					writer.WriteHeader(http.StatusInternalServerError)
					writer.Write([]byte(err.Error()))
					return
				}

				log.Printf("Marshaler %s for %s\n", ContentTypeMarshallers[ct], ct)
				if marshaller, ok := ContentTypeMarshallers[ct]; ok {
					err = marshaller.Unmarshal(buf, inData)
				} else {
					sct := supportedContentTypesMessage
					marshaller := ContentTypeMarshallers["application/json"]
					dataOut, _ := marshaller.Marshal(sct)
					writer.WriteHeader(http.StatusNotAcceptable)
					writer.Write(dataOut)
					return
				}

				if err != nil {
					writer.WriteHeader(http.StatusInternalServerError)
					writer.Write([]byte(err.Error()))
					return
				}
			}
			err = request.ParseForm()
			if err != nil {
				log.Printf("Error %s\n", err)
				writer.WriteHeader(http.StatusInternalServerError)
				writer.Write([]byte(err.Error()))
				return
			}
			restContext := RestContext{PathVariables: mux.Vars(request), QueryVariables: request.Form}
			outData, err := restHandler(inData, restContext)
			//			log.Printf("In here, outData: [%s] of type %s, error [%s] [%s]\n", outData, reflect.TypeOf(outData), err, err == nil)
			if err == nil {
				contentType := writer.Header().Get("Content-Type")
				// This should be ok because the middleware took care of negotiating
				// only the content types we support
				marshaller := ContentTypeMarshallers[contentType]
				if marshaller == nil {
					log.Printf("No marshaler for [%s] found in %s, %s\n", contentType, ContentTypeMarshallers, ContentTypeMarshallers["application/json"])
					writer.WriteHeader(http.StatusUnsupportedMediaType)
					sct := supportedContentTypesMessage
					marshaller := ContentTypeMarshallers["application/json"]
					dataOut, _ := marshaller.Marshal(sct)
					writer.Write(dataOut)
					return
				}
				wireData, err := marshaller.Marshal(outData)
				//				log.Printf("Out data: %s, wire data: %s, error %s\n", outData, wireData, err)
				if err == nil {
					writer.WriteHeader(http.StatusOK)
					writer.Write(wireData)
					return
				}
			}

			// There was an error -- that's the only way we fell through
			// here
			log.Printf("Error %s\n", err)
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(err.Error()))
		}
		return RomanaHandler{httpHandler}
	}

}

// NewRouter creates router for a new service.
func newRouter(routes []Route) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		var handler RestHandler
		handler = route.Handler
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Handler(wrapHandler(handler, route.MakeMessage))
	}
	return router
}

// List of supported content types to return in a
// 406 response.
var supportedContentTypes = []string{"text/plain", "application/vnd.romana.v1+json", "application/vnd.romana+json", "application/json", "application/x-www-form-urlencoded"}

// Above list of supported content types wrapped in a
// struct for converion to JSON.
var supportedContentTypesMessage = struct {
	SupportedContentTypes []string `json:"supported_content_types"`
}{
	supportedContentTypes,
}

// Marshaller is capable of marshalling and unmarshalling data to/from the wire.
type Marshaller interface {
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
}

// jsonMarshaller provides functionality to marshal/unmarshal
// data to/from JSON format.
type jsonMarshaller struct{}

// Marshal takes the provided interface and return []byte
// of its JSON representation.
func (j jsonMarshaller) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal attempts to fill the fields of provided interface
// from the provided JSON sructure.
func (j jsonMarshaller) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// formMarshaller provides functionality to marshal/unmarshal
// data to/from HTML form format.
type formMarshaller struct{}

func (j formMarshaller) Marshal(v interface{}) ([]byte, error) {
	retval := ""
	vPtr := reflect.ValueOf(v)
	vVal := vPtr.Elem()
	vType := reflect.TypeOf(vVal.Interface())
	for i := 0; i < vVal.NumField(); i++ {
		metaField := vType.Field(i)
		field := vVal.Field(i)
		formKey := metaField.Tag.Get("form")
		if len(retval) > 0 {
			retval += "&"
		}
		retval += formKey + "="
		log.Printf("form key of %s is %s\n", metaField.Name, formKey)
		str := ""
		if metaField.Type == stringType {
			str = field.Interface().(string)
		} else {
			toString := field.MethodByName("String")
			log.Printf("Looking for method String on %s: %s\n", field, toString)
			if reflect.Zero(reflect.TypeOf(toString)) != toString {
				toStringResult := toString.Call(nil)
				str = toStringResult[0].String()
			} else {
				log.Printf("Ignoring field %s of %s\n", metaField.Name, v)
				continue
			}
		}
		str = strings.TrimSpace(str)

		retval += str
	}
	return []byte(retval), nil
}

// Unmarshal attempts to take a payload of an HTML form
// (key=value pairs separated by &, application/x-www-form-urlencoded
// MIME) and fill the v structure from it. It is not a universal method,
// and right now is limited to this simple functionality:
// 1. No support for multiple values for the same key (though HTML forms allow it).
// 2. interface v must be one of:
//    a. map[string]interface{}
//    b. Contain string fields for every field in the form OR,
//       implement a Set<Field> method. (Structure tag "form" can be
//       used to map the form key to the structure field if they are
//       different). Here is a supported example:
//       type NetIf struct {
//    	     Mac  string `form:"mac_address"` // Will get set because it's a string.
//	         IP  net.IP `form:"ip_address"`   // Will get set because of SetIP() method below.
//       }
//
//func (netif *NetIf) SetIP(ip string) error {
//	netif.IP = net.ParseIP(ip)
//	if netif.IP == nil {
//		return failedToParseNetif()
//	}
//	return nil
//}
func (f formMarshaller) Unmarshal(data []byte, v interface{}) error {
	log.Printf("Entering formMarshaller.Unmarshal()\n")
	var err error
	dataStr := string(data)
	// We'll keep it simple - make a map and use mapstructure
	vPtr := reflect.ValueOf(v)
	vVal := vPtr.Elem()
	vType := reflect.TypeOf(vVal.Interface())
	kvPairs := strings.Split(dataStr, "&")
	var m map[string]interface{}
	if vType.Kind() == reflect.Map {
		// If the output wanted is a map, then just use it as a map.
		m = *(v.(*map[string]interface{}))
	} else {
		// Otherwise, first mape a temporary map
		m = make(map[string]interface{})
	}
	for i := range kvPairs {
		kv := strings.Split(kvPairs[i], "=")
		// Of course we have to do checking etc...
		key := string(kv[0])
		val := string(kv[1])
		val2, err := url.QueryUnescape(val)
		if err != nil {
			return err
		}
		m[key] = val2
	}
	log.Printf("Unmarshaled form %s to map %s\n", dataStr, m)

	if vType.Kind() == reflect.Map {
		// At this point we already have filled in the map,
		// and map is the type we want, so we return.
		return nil
	}

	for i := 0; i < vVal.NumField(); i++ {
		metaField := vType.Field(i)
		field := vVal.Field(i)
		formKey := metaField.Tag.Get("form")
		formValue := m[formKey]
		log.Printf("Value of %s is %s\n", metaField.Name, formValue)
		if metaField.Type == stringType {
			field.SetString(formValue.(string))
		} else {
			setterMethodName := fmt.Sprintf("Set%s", metaField.Name)
			setterMethod := vPtr.MethodByName(setterMethodName)
			log.Printf("Looking for method %s on %s: %s\n", setterMethodName, vPtr, setterMethod)
			if reflect.Zero(reflect.TypeOf(setterMethod)) != setterMethod {
				valueArg := reflect.ValueOf(formValue)
				valueArgs := []reflect.Value{valueArg}
				result := setterMethod.Call(valueArgs)
				errIfc := result[0].Interface()
				if errIfc != nil {
					return errIfc.(error)
				}
			} else {
				return errors.New(fmt.Sprintf("Unsupported type of field %s: %s", metaField.Name, metaField.Type))
			}

		}
	}

	return err
}

// ContentTypeMarshallers maps MIME type to Marshaller instances
var ContentTypeMarshallers map[string]Marshaller = map[string]Marshaller{
	// If no content type is sent, we will still assume it's JSON
	// and try.
	"":                                  jsonMarshaller{},
	"application/json":                  jsonMarshaller{},
	"application/vnd.romana.v1+json":    jsonMarshaller{},
	"application/vnd.romana+json":       jsonMarshaller{},
	"application/x-www-form-urlencoded": formMarshaller{},
	//	"*/*": jsonMarshaller{},
}

// Authenticator is the interface that will be used by AuthMiddleware
// to provide authentication. Details to be worked out later.
type Authenticator interface {
	// As this is a placeholder, we are not dealing with
	// details yet, tokens vs credentials, principals vs roles, etc.
	Authenticate() Principal
}

type PlaceholderAuth struct {
}

func (p PlaceholderAuth) Authenticate() Principal {
	return Principal{"asdf", []string{"read", "write", "execute"}}
}

// Principal is a placeholder for a Principal structure
// for authentication. We'll leave roles and
// other stuff for later.
type Principal struct {
	Id string
	// This really is a placeholder
	Rights []string
}

// Wrapper for auth
type AuthMiddleware struct {
	Authenticator Authenticator
}

// NewAuth creates AuthMiddleware
func NewAuth() *AuthMiddleware {
	// Should we keep this global?
	auth := PlaceholderAuth{}
	return &AuthMiddleware{auth}
}

func (am AuthMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	p := am.Authenticator.Authenticate()
	rights := p.Rights
	context.Set(r, "Rights", rights)
	// Call the next middleware handler
	next(rw, r)
}

type UnmarshallerMiddleware struct {
}

func NewUnmarshaller() *UnmarshallerMiddleware {
	return &UnmarshallerMiddleware{}
}

type myReader struct{ *bytes.Buffer }

func (r myReader) Close() error { return nil }

const (
	// For passing in Gorilla Mux context the unmarshalled data
	ContextKeyUnmarshalledMap string = "UnmarshalledMap"
	// For passing in Gorilla Mux context path variables

	ContextKeyQueryVariables string = "QueryVars"
	// 	 For passing in Gorilla Mux context the original body data
	ContextKeyOriginalBody string = "OriginalBody"
	ContextKeyMarshaller   string = "Marshaller"
)

// Unmarshals request body if needed. If not acceptable,
// returns an http.StatusNotAcceptable and this ends this
// request's lifecycle.
func (m UnmarshallerMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ct := r.Header.Get("content-type")

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	if len(buf) == 0 {
		next(w, r)
		return
	}
	log.Printf("Marshaler %s for %s\n", ContentTypeMarshallers[ct], ct)
	if marshaller, ok := ContentTypeMarshallers[ct]; ok {
		// Solution due to
		// http://stackoverflow.com/questions/23070876/reading-body-of-http-request-without-modifying-request-state
		// GG: I would not really judge this at all for this purpose until the
		// whole thing about how to use the middlewares settles.
		rdr2 := myReader{bytes.NewBuffer(buf)}
		r.Body = rdr2
		myMap := make(map[string]interface{})
		marshaller.Unmarshal(buf, &myMap)
		context.Set(r, ContextKeyUnmarshalledMap, myMap)
		// TODO
		context.Set(r, ContextKeyOriginalBody, buf)
		context.Set(r, ContextKeyMarshaller, marshaller)
		// Call the next middleware handler
		next(w, r)
	} else {
		sct := supportedContentTypesMessage
		marshaller := ContentTypeMarshallers["application/json"]
		dataOut, _ := marshaller.Marshal(sct)
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write(dataOut)
	}

}

type NegotiatorMiddleware struct {
}

func NewNegotiator() *NegotiatorMiddleware {
	return &NegotiatorMiddleware{}
}

func (negotiator NegotiatorMiddleware) ServeHTTP(writer http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
	// TODO answer with a 406 here?
	accept := request.Header.Get("accept")
	if accept == "*/*" || accept == "" {
		// Force json if it can take anything.
		accept = "application/json"
	}
	format, err := negotiation.NegotiateAccept(accept, supportedContentTypes)
	if err == nil {
		writer.Header().Set("Content-Type", format.Value)
	}
	next(writer, request)
}
