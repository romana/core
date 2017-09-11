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

	"github.com/romana/core/common"
)

// romanaErrorToHTTPError is a helper method that creates an
// HTTP error (one that the middleware automatically converts to the right
// HTTP status code and response) from the provided Romana error, if possible.
// If the provided is not a Romana error, or if no corresponding HTTP errror
// can be provided, the original error is returned. Thus the signature takes a
// generic error and also returns it.
func RomanaErrorToHTTPError(err error) error {
	if err == nil {
		return nil
	}
	switch err := err.(type) {
	case RomanaNotFoundError:
		return common.NewError404(err.Type, fmt.Sprintf("%v", err.Attributes))
	case RomanaExistsError:
		common.NewErrorConflict(err)

	}
	return err
}
