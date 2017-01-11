// Copyright (c) 2016 Pani Networks
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
	"encoding/json"
	"fmt"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
	"math"
	"sync"
)

var (
	IDRingOverflowError          = NewError("No more available IDs")
	IDRingCannotReclaimZeroError = NewError("Cannot reclaim ID 0")
)

// Range represents a range of uint64s that can be
// used as sequential IDs. The range is inclusive.
type Range struct {
	Min uint64
	Max uint64
}

func (irr Range) String() string {
	var max string
	if irr.Max == math.MaxUint64 {
		max = "MaxUint64"
	} else {
		max = fmt.Sprintf("%d", irr.Max)
	}
	s := fmt.Sprintf("[%d-%s]", irr.Min, max)
	return s
}

// idRing is responsible for allocating first available ID. Initially
// the available range is from 1 to math.MaxUint64. As IDs are allocated,
// the range shrinks. IDs can be returned to the ring. An instance of this SHOULD NOT
// be created directly, use NewIDRing() to create it.
type IDRing struct {
	// Ranges is an ordered set of ranges from which .
	// Initially this should include a single Ranges,
	// from 1 to MaxInt.
	// When this is nil, it means that we have exhausted the entire
	// range from 1 to MaxInt, and, unless an ID is reclaimed, no more
	// IDs can be given out.
	// TODO this implementation is probably better (memory-wise) for a lot of allocations, with few
	// reclaimed IDs, as is often the case. But if there are intended to be relatively
	// few allocations and lots of reuse, a faster (less memory-efficient, which doesn't matter
	// at small sizes) would be better. Thus it may make sense to extract
	// an interface and split implementation into 2: intended for mostly allocations and few
	// reclamations, and intended for few allocations with a lot of reclamations.
	Ranges []Range
	// To ensure that GetID and ReclaimID are atomic.
	mutex *sync.Mutex
}

// NewIDRing constructs a new IDRing instance with a single range, from 1 to
// MaxInt, and initialized mutex.
func NewIDRing() IDRing {
	idRing := IDRing{Ranges: []Range{Range{Min: 1, Max: math.MaxUint64}},
		mutex: &sync.Mutex{},
	}
	return idRing
}

// Encode encodes the IDRing into an array of bytes.
func (ir IDRing) Encode() ([]byte, error) {
	return json.Marshal(ir)

}

// DecodeIDRing decodes IDRing object from the byte array.
func DecodeIDRing(data []byte) (IDRing, error) {
	idRing := IDRing{}
	err := json.Unmarshal(data, &idRing)
	if err != nil {
		return idRing, err
	}
	// Create new mutex - we don't serialize it.
	idRing.mutex = &sync.Mutex{}
	return idRing, nil
}

// String returns a human-readable representation of the ring.
func (ir IDRing) String() string {
	s := ""
	if ir.Ranges == nil || len(ir.Ranges) == 0 {
		return "()"
	}

	if len(ir.Ranges) == 1 {
		return ir.Ranges[0].String()
	}

	s += "("
	for i, r := range ir.Ranges {
		if i > 0 {
			s += ", "
		}
		s += r.String()
	}
	s += ")"
	return s
}

// GetID returns the first available ID, starting with 1.
// It will return an IDRingOverflowError if no more IDs can be returned.
func (idRing *IDRing) GetID() (uint64, error) {
	log.Tracef(trace.Inside, "GetID: Trying to get ID from %s", idRing.String())
	idRing.mutex.Lock()
	defer idRing.mutex.Unlock()
	if idRing.Ranges == nil || len(idRing.Ranges) == 0 {
		log.Tracef(trace.Inside, "GetID: Returning error, remaining %s", idRing.String())
		return 0, IDRingOverflowError
	}
	retval := idRing.Ranges[0].Min
	if retval == math.MaxUint64 || retval+1 > idRing.Ranges[0].Max {
		// This range is exhausted, remove it...
		if len(idRing.Ranges) == 1 {
			idRing.Ranges = nil
		} else {
			idRing.Ranges = idRing.Ranges[1:]
		}
	} else {
		idRing.Ranges[0].Min += 1
	}
	log.Tracef(trace.Inside, "GetID: Returning %d, remaining %s", retval, idRing.String())
	return retval, nil
}

// ReclaimID returns the provided ID into the pool, so it can
// be returned again upon some future call to GetID.
func (idRing *IDRing) ReclaimID(id uint64) error {
	log.Tracef(trace.Inside, "ReclaimID: Trying to reclaim ID %d into %s", id, *idRing)
	idRing.mutex.Lock()
	defer idRing.mutex.Unlock()
	if id == 0 {
		log.Tracef(trace.Inside, "ReclaimID: Returning error for 0")
		return IDRingCannotReclaimZeroError
	}
	if idRing.Ranges == nil || len(idRing.Ranges) == 0 {
		idRing.Ranges = []Range{Range{Min: id, Max: id}}
		log.Tracef(trace.Inside, "ReclaimID: Reclaimed ID %d to get %s", id, *idRing)
		return nil
	}

	done := false
	for i, _ := range idRing.Ranges {
		prevRanges := make([]Range, 0)
		if i > 0 {
			prevRanges = idRing.Ranges[0:i]
		}
		curRange := idRing.Ranges[i]
		follRanges := make([]Range, 0)
		if i+1 < len(idRing.Ranges) {
			follRanges = idRing.Ranges[i : i+1]
		}
		log.Tracef(trace.Inside, "ReclaimID: prevRanges %s, curRange %s, follRanges %s", prevRanges, curRange, follRanges)
		if id < curRange.Min {
			// If id is smaller than the lowest bound of the first range, create an
			// range of its own for it, and insert it prior to this current range.
			newRange := Range{Min: id, Max: id}
			newRanges := append(prevRanges, newRange, curRange)
			newRanges = append(newRanges, follRanges...)
			idRing.Ranges = newRanges
			done = true
			break
		}
		if id >= curRange.Min && id <= curRange.Max {
			return NewError("ReclaimID: Cannot reclaim id %d: it has not been allocated and is part of range %d: %s", id, i, *idRing)
		}
	}
	if !done {
		// At this point this can only mean that the ID being
		// reclaimed is higher than the Max of the last range
		// which is not possible.
		return NewError("ReclaimID: Cannot reclaim id %d: it could not been", id)

	}
	// Now we need to merge the ranges
	idRing.mergeRanges()
	log.Tracef(trace.Inside, "ReclaimID: After reclaiming %d, have %s", id, *idRing)
	return nil
}

// mergeRanges will merge contiguous ranges into one, e.g.,
// [1-2], [3-5] would be merged into a single [1-5] range.
func (idRing *IDRing) mergeRanges() {
	// This is a very naive algorithm, a la bubble sort - in a
	// sense that we go over the array of ranges as many times
	// as needed until no merges have occurred.
	// But it'll do for now.
	log.Tracef(trace.Inside, "mergeRanges: Before: %s", *idRing)
	var changes bool
	for {
		changes = false
		newRanges := make([]Range, 0)
		for i, _ := range idRing.Ranges {
			// Prev ranges is ranges from the start up to the
			// current one being examined.
			prevRanges := make([]Range, 0)
			if i > 0 {
				prevRanges = idRing.Ranges[0:i]
			}
			// follRanges are ranges following the current range and one
			// after that (as we look at 2 ranges at a time, i and i+1, to
			// see if they should be merged).
			follRanges := make([]Range, 0)
			if i+2 < len(idRing.Ranges) {
				follRanges = idRing.Ranges[i+2:]
			}
			if i < len(idRing.Ranges)-1 {
				if idRing.Ranges[i].Max == idRing.Ranges[i+1].Min ||
					idRing.Ranges[i].Max+1 == idRing.Ranges[i+1].Min {
					// [1-1],[2-2] should merge to [1-2]
					mergedRange := Range{Min: idRing.Ranges[i].Min,
						Max: idRing.Ranges[i+1].Max,
					}
					newRanges = append(prevRanges, mergedRange)
					newRanges = append(newRanges, follRanges...)
					idRing.Ranges = newRanges
					changes = true
					log.Tracef(trace.Inside, "mergeRanges: %d, prevRanges %s, follRanges %s, newRanges %s", i, prevRanges, follRanges, newRanges)
					log.Tracef(trace.Inside, "mergeRanges: During %s", *idRing)
					break
				}
			}
		}
		if !changes {
			break
		}
	}
	log.Tracef(trace.Inside, "mergeRanges: After: %s", *idRing)
}
