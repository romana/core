// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package agent

import (
	"fmt"
)

// Error codes.
const (
	EcodeDefault = iota + 100
	EcodeShelloutFailed
	EcodeRequestParsingFailed
	EcodeCreateRouteFailed
)

// ErrorMessages provides description for error codes ErrorMessages[Ecode]string.
var ErrorMessages = map[int]string{
	EcodeDefault:              "Unspecified error",
	EcodeShelloutFailed:       "External command unsuccessful",
	EcodeRequestParsingFailed: "Garbage in the request",
	EcodeCreateRouteFailed:    "Can't create IP route",
}

// Error is a structure that represents an error.
type Error struct {
	ErrorCode int
	Message   string
	Cause     string
}

// NewError helps to construct new Error structure.
func NewError(ecode int, cause string) Error {
	return Error{
		ErrorCode: ecode,
		Message:   ErrorMessages[ecode],
		Cause:     cause,
	}
}

// Error is a method to satisfy error interface and returns a string representation of the error.
func (e Error) Error() string {
	return e.Message + " (" + e.Cause + ")"
}

func shelloutError(err error, cmd string, args []string) error {
	return NewError(EcodeShelloutFailed, fmt.Sprintf("%v %v: %v", cmd, args, err))
}

func garbageRequestError(key string) error {
	return NewError(EcodeRequestParsingFailed, key)
}

func requestParseError(fields int) error {
	return NewError(EcodeRequestParsingFailed, fmt.Sprintf("number of parsed fields: %v", fields))
}

func netIfRouteCreateError(err error, netif NetIf) error {
	return NewError(EcodeCreateRouteFailed, fmt.Sprintf("target %v: cause %v", netif, err))
}

func routeCreateError(err error, ip string, mask string, dest string) error {
	return NewError(EcodeCreateRouteFailed, fmt.Sprintf("target %s/%s -> %s: cause %v", ip, mask, dest, err))
}

func agentError(err error) error {
	return NewError(EcodeDefault, fmt.Sprintf("Agent: %v", err))
}

func agentErrorString(str string) error {
	return NewError(EcodeDefault, fmt.Sprintf("Agent: %s", str))
}

func ensureLineError(err error) error {
	return NewError(EcodeShelloutFailed, fmt.Sprintf("Failed to provision static lease: %v", err))
}

func noSuchRouteError() error {
	return NewError(EcodeShelloutFailed, fmt.Sprintf("ERROR: No such route"))
}

func wrongHostError() error {
	return NewError(EcodeDefault, fmt.Sprintf("ERROR: Can't resolve internal IPs. It looks like we're running on the host outside of Romana config"))
}

func failedToParseOtherHosts(s string) error {
	return NewError(EcodeDefault, fmt.Sprintf("ERROR: Failed to parse netmask out of %s in CreateInterhostRoutes", s))
}

func combinedError(s string, err error) error {
	// TODO scheduled for deprecation, all calls must be refactored
	// to analize incoming errorCode and produce new Error instead
	return fmt.Errorf("%s %s", s, err)
}

func failedToParseNetif(details string) error {
	return NewError(EcodeRequestParsingFailed, fmt.Sprintf("ERROR: Failed to parse netif: %s", details))
}
