// Copyright (c) 2015-2017 Pani Networks
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

// Definitions of common structures.

type FindFlag string

const (
	// Flags to store.Find operation
	FindFirst      = "findFirst"
	FindLast       = "findLast"
	FindExactlyOne = "findExactlyOne"
	FindAll        = "findAll"
)

// Here we only keep type definitions and struct definitions with no behavior.

// Constants
const (
	// For passing in Gorilla Mux context the unmarshalled data
	ContextKeyUnmarshalledMap string = "UnmarshalledMap"
	// For passing in Gorilla Mux context path variables
	ContextKeyQueryVariables string = "QueryVars"
	// 	 For passing in Gorilla Mux context the original body data
	ContextKeyOriginalBody string = "OriginalBody"
	ContextKeyMarshaller   string = "Marshaller"
	ContextKeyUser         string = "User"
	ReadWriteTimeoutDelta         = 10

	// Name of the query parameter used for request token
	RequestTokenQueryParameter = "RequestToken"

	HeaderContentType = "content-type"

	Starting ServiceMessage = "Starting."

	// JSON
	TimeoutMessage = "{ \"error\" : \"Timed out\" }"

	// Empty string returned when there is a string return
	// but there is an error so no point in returning any
	// value.
	ErrorNoValue = ""

	// Path for authentication; if this is what is used
	// in the request we will not check the token (because
	// we are attempting to get a token at this point).
	AuthPath = "/auth"

	// Body provided.
	HookExecutableBodyArgument = "body"
)

// LinkResponse structure represents the commonly occurring
// {
//        "href" : "https://<own-addr>",
//        "rel"  : "self"
//  }
// part of the response.
type LinkResponse struct {
	Href string `json:"href,omitempty"`
	Rel  string `json:"rel,omitempty"`
}

// Type definitions
type ServiceMessage string

// Message to register with the root service the actual
// port a service is listening on.
type PortUpdateMessage struct {
	Port uint64 `json:"port"`
}

// RestServiceInfo describes information about a running
// Romana service.
type RestServiceInfo struct {
	// Address being listened on (as host:port)
	Address string
	// Channel to communicate with the service
	Channel chan ServiceMessage
}
