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

package common

import (
	"math"
	"testing"
)

// TestIDRingEncodeDecode ensures that encoding and decoding an IDRing results
// in the struct equivalent to the original.
func TestIDRingEncodeDecode(t *testing.T) {
	var err error
	idRing := NewIDRing(1, math.MaxUint64)

	// 1. Test constructor
	if idRing.Ranges == nil {
		t.Fatalf("Unexpected value of idRing.Ranges: nil")
	}
	if len(idRing.Ranges) != 1 {
		t.Fatalf("Unexpected length of idRing.Ranges: %d, expected 1", len(idRing.Ranges))
	}
	if idRing.Ranges[0].Min != 1 {
		t.Fatalf("Unexpected value of of idRing.Ranges[0].Min: %d, expected 1", idRing.Ranges[0].Min)
	}
	if idRing.Ranges[0].Max != math.MaxUint64 {
		t.Fatalf("Unexpected value of of idRing.Ranges[0].Max: %v, expected 18446744073709551615", idRing.Ranges[0].Max)
	}

	// 2. Test encode/decode
	data, err := idRing.Encode()
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	idRing2, err := DecodeIDRing(data)
	if idRing2.Ranges == nil {
		t.Fatalf("Unexpected value of idRing2.Ranges: nil")
	}
	if len(idRing2.Ranges) != 1 {
		t.Fatalf("Unexpected length of idRing2.Ranges: %d, expected 1", len(idRing2.Ranges))
	}
	if idRing2.Ranges[0].Min != 1 {
		t.Fatalf("Unexpected value of of idRing2.Ranges[0].Min: %d, expected 1", idRing2.Ranges[0].Min)
	}
	if idRing2.Ranges[0].Max != math.MaxUint64 {
		t.Fatalf("Unexpected value of of idRing2.Ranges[0].Max: %v, expected 18446744073709551615", idRing2.Ranges[0].Max)
	}
}

// TestIDRing tests IDRing functionality.
func TestIDRingAllocation(t *testing.T) {
	var err error
	var id uint64
	idRing := NewIDRing(1, math.MaxUint64)

	// 1. Test invert
	invert := idRing.Invert()
	if len(invert) != 0 {
		t.Errorf("Expected empty array for an inversion of an original ring, got %s", invert)
	}

	// 2. Test allocation
	// First ID given out should be 1
	id, err = idRing.GetID()
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	if id != 1 {
		t.Fatalf("Expected 1, got %d", id)
	}

	// IDs should be given out sequentially, let's try getting up to a 100 of them.
	for i := 2; i < 100; i++ {
		id, err := idRing.GetID()
		if err != nil {
			t.Fatalf("Unexpected error %s", err)
		}
		if id != uint64(i) {
			t.Fatalf("Expected %d, got %d", i, id)
		}
	}

	// 3. Test invert again.
	invert = idRing.Invert()
	if len(invert) != 1 {
		t.Errorf("Expected a single range for an inversion, got %s", invert)
	}
	if invert[0].Min != 1 || invert[0].Max != 100 {
		t.Errorf("Expected 1:100, got %d:%d", invert[0].Min, invert[0].Max)
	}

	// 4. Test reclaiming.
	// 500 should be an error, because that ID was never given out.
	err = idRing.ReclaimID(500)
	if err == nil {
		t.Fatalf("Successfully reclaimed 500 into %s, expected error", idRing)
	}

	// All of these should be successful - we are reclaiming all the IDs
	// we got earlier.
	for i := 1; i < 100; i++ {
		err := idRing.ReclaimID(uint64(i))
		if err != nil {
			t.Fatalf("Unexpected error %s", err)
		}
	}
	// We have reclaimed all so now we should have ring from 1 to MaxInt again
	if len(idRing.Ranges) != 1 {
		t.Fatalf("Expected len(idRing.Ranges) to be 1, got %d", len(idRing.Ranges))
	}
	if idRing.Ranges[0].Min != 1 {
		t.Fatalf("Expected idRing.Ranges[0].Min to be 1, got %d", idRing.Ranges[0].Min)
	}
	if idRing.Ranges[0].Max != math.MaxUint64 {
		t.Fatalf("Expected idRing.Ranges[0].Max to be MaxUint64, got %d", idRing.Ranges[0].Max)
	}
}
