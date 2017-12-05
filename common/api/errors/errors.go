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
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package errors

import (
	"fmt"
	"strings"
)

// RomanaNotFoundError represents an error when an entity (or resource)
// is not found. It is a separate error because clients may wish to check for this
// error.
type RomanaNotFoundError struct {
	// Attributes represent key-value pairs used to search
	// for the object.
	Attributes map[string]string
	Type       string
	Message    string
}

// NewRomanaNotFoundError creates a RomanaNotFoundError. Each element
// of attrs is interpreted as a "key=value" pair.
func NewRomanaNotFoundError(message string, t string, attrs ...string) RomanaNotFoundError {
	attrMap := make(map[string]string)
	for _, attr := range attrs {
		kv := strings.SplitN(attr, "=", 2)
		k := kv[0]
		v := kv[1]
		attrMap[k] = v
	}
	err := RomanaNotFoundError{Message: message,
		Type:       t,
		Attributes: attrMap,
	}
	return err
}

func (rnfe RomanaNotFoundError) Error() string {
	if rnfe.Message == "" {
		return fmt.Sprintf("An %s object with attributes %v not found", rnfe.Type, rnfe.Attributes)
	} else {
		return rnfe.Message
	}
}

// RomanaExistsError represents an error when an entity already
// exists.
type RomanaExistsError struct {
	Type string
	// Attributes represent key-value pairs used to add
	// the object.
	Attributes map[string]string
	Object     interface{}
	Message    string
}

func NewRomanaExistsError(obj interface{}, t string, attrs ...string) RomanaExistsError {
	attrMap := make(map[string]string)
	for _, attr := range attrs {
		kv := strings.SplitN(attr, "=", 2)
		k := kv[0]
		v := kv[1]
		attrMap[k] = v
	}
	err := RomanaExistsError{
		Type:       t,
		Object:     obj,
		Attributes: attrMap,
	}
	return err
}

func NewRomanaExistsErrorWithMessage(msg string, obj interface{}, t string, attrs ...string) RomanaExistsError {
	err := NewRomanaExistsError(obj, t, attrs...)
	err.Message = msg
	return err
}

func (ree RomanaExistsError) Error() string {
	if ree.Message == "" {
		return fmt.Sprintf("A[n] '%s' object identified by %+v already exists: %s", ree.Type, ree.Attributes, ree.Object)
	} else {
		return ree.Message
	}
}
