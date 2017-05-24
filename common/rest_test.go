// Copyright (c) 2017 Pani Networks
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

import (
	"fmt"
	"testing"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

func TestPanicHandler(t *testing.T) {
	var err error
	// Create negroni
	negroni := negroni.New()
	negroni.Use(newPanicRecoveryHandler())

	router := mux.NewRouter().StrictSlash(true)
	handlerOk := func(input interface{}, context RestContext) (interface{}, error) {
		return "OK", nil
	}
	route := Route{Handler: handlerOk,
		Method:  "GET",
		Pattern: "/ok",
		AuthZChecker: func(ctx RestContext) bool {
			return true
		},
	}
	wrappedHandler := wrapHandler(handlerOk, route)
	router.
		Methods(route.Method).
		Path(route.Pattern).
		Handler(wrappedHandler)

	handlerPanic := func(input interface{}, context RestContext) (interface{}, error) {
		panic("Panic!!!")
		return "", nil
	}
	route = Route{Handler: handlerOk,
		Method:  "GET",
		Pattern: "/panic",
		AuthZChecker: func(ctx RestContext) bool {
			return true
		},
	}
	wrappedHandler = wrapHandler(handlerPanic, route)
	router.
		Methods(route.Method).
		Path(route.Pattern).
		Handler(wrappedHandler)

	negroni.UseHandler(router)

	readWriteDur, _ := time.ParseDuration("10s")
	svcInfo, err := RunNegroni(negroni, "localhost:0", readWriteDur)
	if err != nil {
		t.Errorf("Unexpected error %s", err)
	}
	t.Log(<-svcInfo.Channel)

	t.Logf("Listening on %s", svcInfo.Address)

	rc, err := NewRestClient(RestClientConfig{
		TimeoutMillis: 10000,
	})
	if err != nil {
		t.Errorf("Unexpected error %s", err)
	}

	url := fmt.Sprintf("http://%s", svcInfo.Address)
	s := ""

	okUrl := fmt.Sprintf("%s/ok", url)
	err = rc.Get(okUrl, &s)
	if err != nil {
		t.Errorf("Unexpected error on %s: %s", okUrl, err)
	}
	t.Logf("Got %s from %s", s, okUrl)

	panicUrl := fmt.Sprintf("%s/panic", url)
	err = rc.Get(panicUrl, &s)
	if err == nil {
		t.Errorf("Expected error on %s, got %+v", panicUrl, s)
	}
	switch err := err.(type) {
	case HttpError:
		if err.StatusCode != 500 {
			t.Errorf("Unexpected error on %s: %s", okUrl, err)
		}
		t.Logf("Got expected error on panic: %+v", s)
	default:
		t.Errorf("Unexpected error on %s: %s", okUrl, err)
	}
}
