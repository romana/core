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
	"errors"
	"fmt"
	"github.com/jinzhu/gorm"
	"net/http"
	"os/exec"
)

// NewError constructs an error by formatting
// text with arguments.
func NewError(text string, args ...interface{}) error {
	return errors.New(fmt.Sprintf(text, args))
}

// HttpError is a structure that represents, well, an HTTP error.
type HttpError struct {
	// HTTP status code
	StatusCode int         `json:"status_code"`
	Details    interface{} `json:"details,omitempty"`
	// ResourceId specifies the relevant resource ID, if applicable
	ResourceID string `json:"resource_id,omitempty"`
	// ResourceType specifies the relevant resource type, if applicable
	ResourceType string `json:"resource_type,omitempty"`
	SeeAlso      string `json:"see_also, omitempty"`
}

// StatusText returns the string value of the HttpError corresponding
// to the StatusCode.
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

type ExecErrorDetails struct {
	Error string
	// TODO add when we move to Go 1.6
	//	Stderr string
}

// NewError500 creates an HttpError with 500 (http.StatusInternalServerError) status code.
func NewError500(details interface{}) HttpError {
	retval := HttpError{StatusCode: http.StatusInternalServerError}
	switch details := details.(type) {
	case *exec.ExitError:
		retval.Details = ExecErrorDetails{Error: details.Error()} //, Stderr: string(details.Stderr)}
	case *MultiError:
		errors := details.GetErrors()
		if len(errors) > 0 {
			arr := make([]string, len(errors))
			for i, e := range errors {
				arr[i] = e.Error()
			}
			retval.Details = arr
		} else {
			retval.Details = "Unknown error."
		}
	default:
		retval.Details = details
	}
	return retval
}

// NewError400 creates an HttpError with 400 (http.StatusBadRequest) status code.
func NewError400(details interface{}) HttpError {
	return HttpError{StatusCode: http.StatusBadRequest, Details: details}
}

// NewErrorConflict creates an HttpError with 409 (http.StatusConflict) status code.
func NewErrorConflict(details interface{}) HttpError {
	return HttpError{StatusCode: http.StatusConflict, Details: details}
}

// NewUnprocessableEntityError creates an HttpError with 423
// (StatusUnprocessableEntity) status code.
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

// Add adds an error to the MultiError object.
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

// GetErrors returns all errors in this MultiError object.
func (m *MultiError) GetErrors() []error {
	return m.errors
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

// MakeMultiError creates a single error object out of an array of
// errors as follows:
// 1. If the array is empty or nil, nil is returned
// 2. If the array has exactly 1 element, that element is returned
// 3. Otherwise, a MultiError is returned.
func MakeMultiError(errors []error) error {
	if errors == nil {
		return nil
	}
	if len(errors) == 0 {
		return nil
	}
	if len(errors) == 1 {
		return errors[0]
	}
	return &MultiError{errors}
}

// GetDbErrors creates MultiError on error from DB.
func GetDbErrors(db *gorm.DB) error {
	errors := db.GetErrors()
	if errors == nil {
		if db.Error != nil {
			return DbToHttpError(db.Error)
		}
		return nil
	}
	// If errors array is present, it already includes the db.Error value,
	// so we do not need to include it.
	specificErrors := make([]error, len(errors))
	for i, err := range errors {
		specificErrors[i] = DbToHttpError(err)
	}
	return MakeMultiError(specificErrors)
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
