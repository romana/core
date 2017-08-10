// Copyright (c) 2016-2017 Pani Networks
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

package idring

import "sort"

type rangeSorter []Range

func (a rangeSorter) Len() int           { return len(a) }
func (a rangeSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a rangeSorter) Less(i, j int) bool { return a[i].Min < a[j].Min }

// Merge a slice of ranges combining adjacent ranges together
// and skipping included ranges.
func Merge(ranges []Range) []Range {
	if len(ranges) < 2 {
		return ranges
	}

	var result []Range
	sort.Sort(rangeSorter(ranges))
	for i, _ := range ranges {
		if len(result) == 0 {
			result = append(result, ranges[i])
			continue
		}

		resultLastIndex := len(result) - 1
		lastResult := result[resultLastIndex]

		// skip if current element fully included
		// in last result element
		if lastResult.Min <= ranges[i].Min && lastResult.Max >= ranges[i].Max {
			continue
		}

		// merge
		if lastResult.Max+1 >= ranges[i].Min {
			result[resultLastIndex] = Range{lastResult.Min, ranges[i].Max}
			continue
		}

		// can't merge, add as is
		result = append(result, ranges[i])
	}

	return result
}
