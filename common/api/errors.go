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

package api

import "fmt"

// RomanaNotFoundError represents an error when an entity (or resource)
// is not found. It is a separate error because clients may wish to check for this
// error.
type RomanaNotFoundError struct {
	// ResourceID specifies the relevant resource ID, if applicable
	ResourceID string
	// ResourceType specifies the relevant resource type, if applicable
	ResourceType string
}

func (rnfe RomanaNotFoundError) Error() string {
	return fmt.Sprintf("Not found: Resource %s of type %s", rnfe.ResourceID, rnfe.ResourceType)
}
