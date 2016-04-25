// Copyright (c) 2015 Pani Networks
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

// Various errors.

import (
//	"encoding/json"
	"errors"
	"fmt"
	"github.com/jinzhu/gorm"
	"net/http"
)

// NewError constructs an error by formatting
// text with arguments.
func NewError(text string, args ...interface{}) error {
	return errors.New(fmt.Sprintf(text, args))
}

// HttpError is a structure that represents, well, an HTTP error.
type HttpError struct {
	StatusCode int         `json:"status_code"`
	Details    interface{} `json:"details,omitempty"`
	// ResourceId specifies the relevant resource ID, if applicable
	ResourceID string `json:"resource_id,omitempty"`
	// ResourceId specifies the relevant resource type, if applicable
	ResourceType string `json:"resource_id,omitempty"`
	SeeAlso      string `json:"see_also, omitempty"`
}

func (err HttpError) StatusText() string {
	switch err.StatusCode {
	case StatusUnprocessableEntity:
		return "Unprocessable entity"
	default:
		return http.StatusText(err.StatusCode)
	}
}

const (
	// 422 (unprocessable entity http://www.restpatterns.org/HTTP_Status_Codes/422_-_Unprocessable_Entity)
	// is not in net/http yet.
	StatusUnprocessableEntity = 422
)

func NewError500(details interface{}) HttpError {
	return HttpError{StatusCode: http.StatusInternalServerError, Details: details}
}

func NewError400(details interface{}) HttpError {
	return HttpError{StatusCode: http.StatusBadRequest, Details: details}
}

func NewUnprocessableEntityError(details interface{}) HttpError {
	return HttpError{StatusCode: StatusUnprocessableEntity, Details: details}
}

// NewError404 creates a 404 NOT FOUND message.
func NewError404(resourceType string, resourceID string) HttpError {
	return HttpError{StatusCode: http.StatusNotFound, ResourceType: resourceType, ResourceID: resourceID}
}

// String returns formatted HTTP error for human consumption.
func (httpErr HttpError) Error() string {
	s := fmt.Sprintf("%d %s", httpErr.StatusCode, httpErr.StatusText())
	if httpErr.ResourceType != "" {
		s += fmt.Sprintf("\nResource type: %s", httpErr.ResourceType)
	}
	if httpErr.ResourceID != "" {
		s += fmt.Sprintf("\nResource ID: %s", httpErr.ResourceID)
	}
	if httpErr.Details != nil {
		s += fmt.Sprintf("\nDetails: %v", httpErr.Details)
	}
	return s
}

// NewError helps to construct new Error structure.
func NewHttpError(code int, details interface{}) HttpError {
	return HttpError{
		StatusCode: code,
		Details:    details,
	}
}

// MultiError is a facility to collect multiple number of errors but
// present them as a single error interface. For example,
// GORM does not return errors at every turn. It accumulates them and returns
// them whenever you feel like calling GetErrors() (https://godoc.org/github.com/jinzhu/gorm#DB.GetErrors).
// Since this is not consistent with the rest of the code, I prefer to isolate it
// here and make an adapter.
type MultiError struct {
	errors []error
}

func (me MultiError) Add(err error) {
	if me.errors == nil {
		me.errors = make([]error, 1)
		me.errors[0] = err
	} else {
		me.errors = append(me.errors, err)
	}
}

// NewMultiError creates a new MultiError object
// to which errors can be added.
func NewMultiError() *MultiError {
	return &MultiError{}
}

// GetError returns nil if there are no
// underlying errors, the single error if there is
// only one, and the MultiError object if there is
// more than one.
func (m *MultiError) GetError() error {
	if m.errors == nil {
		return nil
	}
	if len(m.errors) == 0 {
		return nil
	}
	if len(m.errors) == 1 {
		return m.errors[0]
	}
	return m
}

// MakeMultiError creates a single MultiError (or nil!) out of an array of
// error objects.
func MakeMultiError(errors []error) error {
	if errors == nil {
		return nil
	}
	if len(errors) == 0 {
		return nil
	}
	return &MultiError{errors}
}

// GetDbErrors creates MultiError or error from DB.
func GetDbErrors(db *gorm.DB) error {
	errors := db.GetErrors()
	if errors == nil {
		if db.Error != nil {
			return db.Error
		} else {
			return nil
		}
	} else {
		if db.Error != nil {
			errors = append(errors, db.Error)
		}
		return MakeMultiError(errors)
	}
	return nil
}

// Error satisfies Error method on error interface and returns
// a concatenated string of all error messages.
func (m *MultiError) Error() string {
	s := ""
	for i := range m.errors {
		if len(s) > 0 {
			s += "; "
		}
		s += m.errors[i].Error()
	}
	return s
}
