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

// Package common contains things related to the REST framework.
package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/K-Phoen/negotiation"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/pborman/uuid"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	//	"log"
	"net/http"
)

// RestContext contains the context of the REST request other
// than the body data that has been unmarshaled.
type RestContext struct {
	// Path variables as described in https://godoc.org/code.google.com/p/gorilla/mux
	PathVariables map[string]string
	// QueryVariables stores key-value-list map of query variables, see url.Values
	// for more details.
	QueryVariables url.Values
	// Unique identifier for a request.
	RequestToken string
	Roles        []Role
	// Output of the hook if any run before the execution of the handler.
	HookOutput string
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

// MakeMessage is a factory function, which should return a pointer to
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

	// Whether this route is using a request token. If true, the
	// request token will be parsed out of the request and made
	// available in RestContext. It can then
	// used by the handler to achieve idempotence.
	UseRequestToken bool

	Hook *Hook
}

// Routes provided by each service.
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

// write500 writes out a 500 error based on provided err
func write500(writer http.ResponseWriter, m Marshaller, err error) {
	writer.WriteHeader(http.StatusInternalServerError)
	httpErr := NewError500(err)
	// Should never error out - it's a struct we know.
	outData, _ := m.Marshal(httpErr)
	writer.Write(outData)
}

// write400 writes out a 400 error based on provided err
func write400(writer http.ResponseWriter, m Marshaller, request string, err error) {
	writer.WriteHeader(http.StatusInternalServerError)
	httpErr := NewError400(err.Error(), request)
	// Should never error out - it's a struct we know.
	outData, _ := m.Marshal(httpErr)
	writer.Write(outData)
}

// doHook runs the Executable specified in route.Hook
// if the before parameter provided here (before or after) matches that
// of before value in route.Hook. It returns stdout and stderr
// from the executable, or an error.
func doHook(before bool, route Route, restContext RestContext, body string) (string, error) {
	hook := route.Hook
	if hook == nil {
		log.Printf("doHook(): No hook for %s %s", route.Method, route.Pattern)
		return "", nil
	}
	hookInfo := fmt.Sprintf("Hook for %s %s: %s", route.Method, route.Pattern, hook.Executable)
	if before && strings.ToLower(hook.When) != "before" {
		log.Printf("doHook(): We are in before and %s is for after", hookInfo)
		return "", nil
	}
	if !before && strings.ToLower(hook.When) != "after" {
		log.Printf("doHook(): We are in after and %s is for before", hookInfo)
		return "", nil
	}
	// Path variables (e.g., id in /foo/{id}) will be passed to the executable as a
	// list of key=value pairs.
	pathVars := restContext.PathVariables
	// Query variables from this URL call will also be provided in the
	// above manner.
	queryVars := restContext.QueryVariables
	// One more element is needed - body=<body> of the request will be provided
	// as CLI argument.
	clArgs := make([]string, len(pathVars)+len(queryVars)+1)
	// Add body argument.
	clArgs[0] = fmt.Sprintf("%s=%s", HookExecutableBodyArgument, body)

	// Add pathVars arguments.
	i := 1
	for k, v := range pathVars {
		clArgs[i] = fmt.Sprintf("%s=%s", k, v)
		i++
	}

	// Add query argument.
	for k, v := range queryVars {
		clArgs[i] = fmt.Sprintf("%s=%s", k, v)
		i++
	}

	var writer io.Writer
	var err error
	writer = nil
	if hook.Output != "" {
		log.Printf("doHook(): Writing output of %s to %s", hookInfo, hook.Output)
		writer, err = os.Create(hook.Output)
		if err != nil {
			return "", err
		}
	} else {
		log.Printf("doHook(): No output specified for %s", hookInfo)
	}
	log.Printf("doHook(): Running hook %s with %s", hook.Executable, clArgs)
	cmd := exec.Command(hook.Executable, clArgs...)
	out, errProcess := cmd.CombinedOutput()
	outStr := string(out)
	log.Printf("\n---------------------------------\n%s\n---------------------------------\n", outStr)
	if writer != nil {
		_, err = writer.Write(out)
		if err != nil {
			return outStr, err
		}
	}
	return outStr, errProcess
}

// wrapHandler wraps the RestHandler function, which deals
// with application logic into an instance of http.HandlerFunc
// which deals with raw HTTP request and response. The wrapper
// is intended to transparently deal with converting data to/from
// the wire format into internal representations.
func wrapHandler(restHandler RestHandler, route Route) http.Handler {
	// TODO
	// This function is very long. Could we please break it up into a few smaller functions
	// (with self-documenting names), which are called from within this function?
	makeMessage := route.MakeMessage
	log.Printf("Entering wrapHandler(%v,%v)", restHandler, route)
	if route.Hook != nil {
		log.Printf("wrapHandler(): %s %s %s", route.Method, route.Pattern, route.Hook.Executable)
	}
	if makeMessage != nil && reflect.TypeOf(makeMessage()) == requestType {
		// This would mean the handler actually wants access to raw request/response
		// Fine, then...
		httpHandler := func(writer http.ResponseWriter, request *http.Request) {
			err := request.ParseForm()
			if err != nil {
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write([]byte(err.Error()))
				return
			}
			restContext := RestContext{PathVariables: mux.Vars(request), QueryVariables: request.Form}
			respReq := UnwrappedRestHandlerInput{writer, request}

			marshaller := ContentTypeMarshallers["application/json"]
			log.Printf("doHook() will be called before %s %s", route.Method, route.Pattern)
			out, err := doHook(true, route, restContext, "")
			if err != nil {
				write500(writer, marshaller, err)
				return
			}
			restContext.HookOutput = out
			restHandler(respReq, restContext)
			log.Printf("doHook() will be called after %s %s", route.Method, route.Pattern)

			_, err = doHook(false, route, restContext, "")
			if err != nil {
				write500(writer, marshaller, err)
				return
			}
		}
		return RomanaHandler{httpHandler}
	} else {
		httpHandler := func(writer http.ResponseWriter, request *http.Request) {
			bufStr := ""
			var inData interface{}
			if makeMessage == nil {
				inData = nil
			} else {
				inData = makeMessage()
			}
			var err error
			contentType := writer.Header().Get("Content-Type")
			// This should be ok because the middleware took care of negotiating
			// only the content types we support
			marshaller := ContentTypeMarshallers[contentType]
			defaultMarshaller := ContentTypeMarshallers["application/json"]

			if marshaller == nil {
				// This should never happen... Just in case...
				log.Printf("No marshaler for [%s] found in %s, %s\n", contentType, ContentTypeMarshallers, ContentTypeMarshallers["application/json"])
				writer.WriteHeader(http.StatusUnsupportedMediaType)
				sct := supportedContentTypesMessage
				dataOut, _ := defaultMarshaller.Marshal(sct)
				writer.Write(dataOut)
				return
			}

			if inData != nil {
				log.Printf("httpHandler: inData addr: %d\n", &inData)
				ct := request.Header.Get("content-type")
				buf, err := ioutil.ReadAll(request.Body)
				bufStr = string(buf)
				log.Printf("Read %s\n", bufStr)
				if err != nil {
					// Error reading...
					write500(writer, marshaller, err)
				}

				if unmarshaller, ok := ContentTypeMarshallers[ct]; ok {
					err = unmarshaller.Unmarshal(buf, inData)
					if err != nil {
						// Error unmarshalling...
						write400(writer, marshaller, string(buf), err)
						return
					}
				} else {
					// Cannot unmarshal
					dataOut, _ := marshaller.Marshal(supportedContentTypesMessage)
					writer.WriteHeader(http.StatusNotAcceptable)
					writer.Write(dataOut)
					return
				}
			}

			err = request.ParseForm()
			if err != nil {
				// Cannot parse form...
				write400(writer, marshaller, request.RequestURI, err)
				return
			}
			var token string
			if route.UseRequestToken {
				if inData != nil {
					v := reflect.Indirect(reflect.ValueOf(inData)).FieldByName(RequestTokenQueryParameter)
					if v.IsValid() {
						token = v.String()
						log.Printf("Token from payload %s\n", token)
					} else {
						tokens := request.Form[RequestTokenQueryParameter]
						if len(tokens) != 1 {
							token = uuid.New()
							log.Printf("Token created %s\n", token)
						} else {
							log.Printf("Token from query string %s\n", token)
						}
						if len(tokens) == 0 {
							// Token was not sent, the caller does it at his own
							// risk. There will be no idempotence.
							token = "1"
						} else {
							token = tokens[0]
						}
					}
				}
			}
			restContext := RestContext{PathVariables: mux.Vars(request), QueryVariables: request.Form, RequestToken: token}
			if route.Hook != nil {
				log.Printf("doHook() will be called before %s %s: %s", route.Method, route.Pattern, route.Hook.Executable)
			}
			out, err := doHook(true, route, restContext, bufStr)
			if err != nil {
				write500(writer, marshaller, err)
				return
			}
			restContext.HookOutput = out
			outData, err := restHandler(inData, restContext)
			if err == nil {
				if route.Hook != nil {
					log.Printf("doHook() will be called after %s %s: %s", route.Method, route.Pattern, route.Hook.Executable)
				}
				out, err = doHook(false, route, restContext, bufStr)
				if err != nil {
					write500(writer, marshaller, err)
					return
				}
				wireData, err := marshaller.Marshal(outData)
				//				log.Printf("Out data: %s, wire data: %s, error %s\n", outData, wireData, err)
				if err == nil {
					writer.WriteHeader(http.StatusOK)
					writer.Write(wireData)
					return
				} else {
					write500(writer, marshaller, err)
					return
				}
			} else {
				switch err := err.(type) {
				case HttpError:
					writer.WriteHeader(err.StatusCode)
					// Should never error out - it's a struct we know.
					outData, _ := marshaller.Marshal(err)
					writer.Write(outData)
				default:
					// Error reading...
					write500(writer, marshaller, err)
				}
				return
			}
		}
		return RomanaHandler{httpHandler}
	}

}

// NewRouter creates router for a new service.
func newRouter(routes []Route) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		handler := route.Handler
		if route.Hook != nil {
			log.Printf("Calling wrapHandler with %s %s %s", route.Method, route.Pattern, route.Hook.Executable)
		}
		wrappedHandler := wrapHandler(handler, route)
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Handler(wrappedHandler)
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
		// Otherwise, first make a temporary map
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
				return fmt.Errorf("Unsupported type of field %s: %s", metaField.Name, metaField.Type)
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

// AuthMiddleware wrapper for auth.
type AuthMiddleware struct {
	PublicKey []byte
}

// If the path of request is common.AuthPath, this does nothing, as
// the request is for authentication in the first place. Otherwise,
// checks token from request. If the token is not valid, returns a
// 403 FORBIDDEN status.
func (am AuthMiddleware) ServeHTTP(writer http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
	if request.URL.Path == AuthPath {
		// Let this one through, no token yet.
		next(writer, request)
		return
	}
	contentType := writer.Header().Get("Content-Type")
	marshaller := ContentTypeMarshallers[contentType]

	if am.PublicKey != nil {
		f := func(token *jwt.Token) (interface{}, error) {
			return am.PublicKey, nil
		}
		log.Printf("Parsing request for auth token\n")
		token, err := jwt.ParseFromRequest(request, f)

		if err != nil {
			writer.WriteHeader(http.StatusForbidden)
			httpErr := NewHttpError(http.StatusForbidden, err.Error())
			outData, _ := marshaller.Marshal(httpErr)
			writer.Write(outData)
			return
		}
		if !token.Valid {
			writer.WriteHeader(http.StatusForbidden)
			httpErr := NewHttpError(http.StatusForbidden, "Invalid token.")
			outData, _ := marshaller.Marshal(httpErr)
			writer.Write(outData)
			return
		}

		context.Set(request, ContextKeyRoles, token.Claims["roles"].([]string))
	}
	next(writer, request)
}

type UnmarshallerMiddleware struct {
}

func NewUnmarshaller() *UnmarshallerMiddleware {
	return &UnmarshallerMiddleware{}
}

type myReader struct{ *bytes.Buffer }

func (r myReader) Close() error { return nil }

// Unmarshals request body if needed. If not acceptable,
// returns an http.StatusNotAcceptable and this ends this
// request's lifecycle.
func (m UnmarshallerMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ct := r.Header.Get(HeaderContentType)

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
