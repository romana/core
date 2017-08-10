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

import "testing"

func TestMerge(t *testing.T) {
	cases := []struct {
		name   string
		ranges []Range
		test   func([]Range) bool
	}{
		{
			name:   "Full collapse",
			ranges: []Range{Range{Min: 43, Max: 44}, Range{Min: 45, Max: 48}, Range{Min: 40, Max: 43}},
			test:   func(r []Range) bool { return r[0].Min == 40 && r[0].Max == 48 },
		},
		{
			name:   "Merge adjacent",
			ranges: []Range{Range{Min: 43, Max: 44}, Range{Min: 45, Max: 48}},
			test:   func(r []Range) bool { return r[0].Min == 43 && r[0].Max == 48 },
		},
		{
			name:   "Merge adjacent2",
			ranges: []Range{Range{Min: 43, Max: 45}, Range{Min: 45, Max: 48}},
			test:   func(r []Range) bool { return r[0].Min == 43 && r[0].Max == 48 },
		},
		{
			name:   "Merge overlap",
			ranges: []Range{Range{Min: 43, Max: 47}, Range{Min: 45, Max: 48}},
			test:   func(r []Range) bool { return r[0].Min == 43 && r[0].Max == 48 },
		},
		{
			name:   "Skip included",
			ranges: []Range{Range{Min: 45, Max: 47}, Range{Min: 40, Max: 40}, Range{Min: 40, Max: 43}},
			test:   func(r []Range) bool { return r[0].Min == 40 && r[1].Max == 47 },
		},
		{
			name:   "Dont merge unmergable",
			ranges: []Range{Range{Min: 45, Max: 47}, Range{Min: 40, Max: 41}},
			test:   func(r []Range) bool { return r[0].Min == 40 && r[1].Max == 47 },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Merge(tc.ranges)
			t.Logf("Name %s, result %+v", tc.name, r)
			if !tc.test(r) {
				t.Fatal(tc.name)
			}
		})
	}
}
