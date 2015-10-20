// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// This file contains things related to the REST framework.

// Common utilities and types that do not fit into other files
// in this package
package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// This only temporarily is a generic interface.
// It will return a Pani message of some sort that is
// more introspectable down the road. But for that
type Message interface {
}

// Service is the interface that microservices implement.
type Service interface {
	// SetConfig sets the configuration, validating it if needed
	// and returning an error if not valid.
	SetConfig(config ServiceConfig) error

	// Returns the routes that this service works with
	Routes() Routes
}

type RestClient struct {
	URL string
}

func (rc RestClient) HttpGet(url string) (Message, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", rc.URL+url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("accept", "application/vnd.pani.v1+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ifc Message
	fmt.Println("Received ", string(body))
	err = json.Unmarshal(body, &ifc)
	if err != nil {
		return nil, err
	} else {
		return ifc, nil
	}
}
