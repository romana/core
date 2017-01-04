// Copyright (c) 2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package hasher

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/romana/core/common"
	"sort"
	"strings"
)

// HashRomanaTenants generates unique hash for a list of romana tenants.
func HashRomanaTenants(tenants []common.Tenant) string {
	var hashes []string
	for _, t := range tenants {
		hashes = append(hashes, HashRomanaTenant(t))
	}

	return HashListOfStrings(hashes)
}

// HashListOfStrings generates sha1 hash from a list of strings.
func HashListOfStrings(hashes []string) string {
	data := strings.Join(hashes, "")
	hasher := sha1.New()
	hasher.Write([]byte(data))
	sum := hasher.Sum(nil)

	return fmt.Sprint(hex.EncodeToString(sum))
}

// HashRomanaTenant generates sha1 hash from a canonical form of the tenant.
func HashRomanaTenant(tenant common.Tenant) string {
	data := Tenant(tenant).String()

	hasher := sha1.New()
	hasher.Write([]byte(data))
	sum := hasher.Sum(nil)

	return fmt.Sprint(hex.EncodeToString(sum))

}

// Tenant wraps tenant.Tenant to provide new behavior.
type Tenant common.Tenant

// String generates canonical representation of a Tenant.
func (t Tenant) String() string {
	return fmt.Sprintf("Tenant %d: ExternalID=%s,Name=%s,NetworkID=%d,Segments=%s", t.ID, t.ExternalID, t.Name, t.NetworkID, Segments{}.From(t.Segments).Sort())
}

// Segment wraps tenant.Segment to provide new behavior.
type Segment common.Segment

// String generates canonical representation of a Segment.
func (s Segment) String() string {
	return fmt.Sprintf("Segment %d: ExternalID=%s,TenantID=%d,Name=%s,NetworkID=%d", s.ID, s.ExternalID, s.TenantID, s.Name, s.NetworkID)
}

// Segments aliases []Segment to provide methods for sort.Interface.
type Segments []Segment

// Len implements sort.Interface.
func (p Segments) Len() int { return len(p) }

// Swap implements sort.Interface.
func (p Segments) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// Less implements sort.Interface, compares canonical string representations of a Segment.
func (p Segments) Less(i, j int) bool { return p[i].String() < p[j].String() }

// Sort is a convinience method that sorts and allows chaining.
func (p Segments) Sort() Segments {
	sort.Sort(p)
	return p
}

// From initializes Segments from a []tenant.Segment.
func (s Segments) From(originalSegments []common.Segment) (segments Segments) {
	for _, segment := range originalSegments {
		segments = append(segments, Segment(segment))
	}
	return segments
}
