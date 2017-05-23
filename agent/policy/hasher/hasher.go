// Copyright (c) 2016 Pani Networks
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
	"strings"
)

// HashRomanaPolicies generates unique hash for a list of romana policies.
func HashRomanaPolicies(policies []common.Policy) string {
	var hashes []string
	for _, policy := range policies {
		hashes = append(hashes, HashRomanaPolicy(policy))
	}

	return HashListOfStrings(hashes)
}

// HashRomanaPolicies generates sha1 hash from a canonical form of the policy.
func HashRomanaPolicy(policy common.Policy) string {
	sorted := PolicyToCanonical(policy)

	var data string

	data = fmt.Sprintf("%s.%s.%s.%d.%s", policy.Direction, policy.Description, policy.Name, policy.ID, policy.ExternalID)

	for _, e := range sorted.AppliedTo {
		data = fmt.Sprintf("%s.%s", data, EndpointToString(e))
	}

	for _, i := range sorted.Ingress {
		for _, e := range i.Peers {
			data = fmt.Sprintf("%s.%s", data, EndpointToString(e))
		}

		for _, r := range i.Rules {
			data = fmt.Sprintf("%s.%s%d%d%t", data, r.Protocol, r.IcmpType, r.IcmpCode, r.IsStateful)

			for _, p := range r.Ports {
				data = fmt.Sprintf("%s%d", data, p)
			}

			for _, p := range r.PortRanges {
				data = fmt.Sprintf("%s%d%d", data, p[0], p[1])
			}
		}
	}

	hasher := sha1.New()
	hasher.Write([]byte(data))
	sum := hasher.Sum(nil)

	return fmt.Sprint(hex.EncodeToString(sum))

}

// HashListOfStrings generates sha1 hash from a list of strings.
func HashListOfStrings(hashes []string) string {
	data := strings.Join(hashes, "")
	hasher := sha1.New()
	hasher.Write([]byte(data))
	sum := hasher.Sum(nil)

	return fmt.Sprint(hex.EncodeToString(sum))
}
