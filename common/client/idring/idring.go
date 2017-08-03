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

import (
	"fmt"
	"math"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
)

var (
	IDRingOverflowError = common.NewError("No more available IDs")
)

// Range represents a range of uint64s that can be
// used as sequential IDs. The range is inclusive (meaning
// that the first available ID is Min, and the last is Max).
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

// IDRing is responsible for allocating first available ID. Initially
// the available range is from OrigMin to OrigMax as provided in the creation.
// As IDs are allocated (see GetID), the range shrinks. IDs can be returned
// to the Ring (see ReclaimID). An instance of this SHOULD NOT
// be created directly, use NewIDRing() to create it.
type IDRing struct {
	// Ranges is an ordered set of ranges from which we allocate IDs.
	// Initially this should include a single Range.
	// When this is nil, it means that we have exhausted the entire
	// range from OrigMin to OrigMax, and, unless an ID is reclaimed, no more
	// IDs can be given out.
	// TODO this implementation is probably better (memory-wise) for a lot of allocations, with few
	// reclaimed IDs, as is often the case. But if there are intended to be relatively
	// few allocations and lots of reuse, a faster (less memory-efficient, which doesn't matter
	// at small sizes) would be better. Thus it may make sense to extract
	// an interface and split implementation into 2: intended for mostly allocations and few
	// reclamations, and intended for few allocations with a lot of reclamations.
	Ranges []Range
	// To ensure that GetID and ReclaimID are atomic; but must be provided by the
	// caller. If not provided, it is assumed the locking guarantees are provided
	// elsewhere.
	locker  sync.Locker
	OrigMin uint64
	OrigMax uint64
}

// NewIDRing constructs a new IDRing instance with a single range for
// provided min and max
func NewIDRing(min uint64, max uint64, locker sync.Locker) *IDRing {
	r := Range{Min: min,
		Max: max,
	}
	idRing := IDRing{Ranges: []Range{r},
		locker:  locker,
		OrigMin: min,
		OrigMax: max,
	}
	return &idRing
}

// String returns a human-readable representation of the ring.
func (ir IDRing) String() string {
	if ir.Ranges == nil || len(ir.Ranges) == 0 {
		return "()"
	}
	sBegin := fmt.Sprintf("{%d ", ir.OrigMin)
	sEnd := fmt.Sprintf(" %d}", ir.OrigMax)
	if len(ir.Ranges) == 1 {
		return sBegin + ir.Ranges[0].String() + sEnd
	}

	s := sBegin + "("
	for i, r := range ir.Ranges {
		if i > 0 {
			s += ", "
		}
		s += r.String()
	}
	s += ")" + sEnd
	return s
}

// Invert() returns an IDRing that is the inverse of this IDRing
// (that is, containing Ranges that are ranges not of available, but
// of taken IDs).
func (ir IDRing) Invert() *IDRing {
	if ir.locker != nil {
		ir.locker.Lock()
		defer ir.locker.Unlock()
	}
	log.Tracef(trace.Inside, "Attempting to invert %s", ir)
	if len(ir.Ranges) == 0 {
		// All filled up.
		r := Range{Min: ir.OrigMin, Max: ir.OrigMax}
		ranges := []Range{r}
		retval := IDRing{OrigMax: ir.OrigMax,
			OrigMin: ir.OrigMin,
			Ranges:  ranges,
			locker:  ir.locker,
		}
		log.Tracef(trace.Private, "Inversion of %s is %s", ir, retval)
		return &retval
	}
	ranges := make([]Range, 0)

	prevMin := ir.OrigMin

	for _, r := range ir.Ranges {
		if prevMin < r.Min {
			ranges = append(ranges, Range{Min: prevMin, Max: r.Min - 1})
			if r.Max == ir.OrigMax {
				prevMin = r.Max
			} else {
				prevMin = r.Max + 1
			}
		}
	}
	lastRange := ir.Ranges[len(ir.Ranges)-1]
	if lastRange.Max < ir.OrigMax {
		ranges = append(ranges, Range{Min: lastRange.Max + 1, Max: ir.OrigMax})
	}

	retval := IDRing{OrigMax: ir.OrigMax,
		OrigMin: ir.OrigMin,
		Ranges:  ranges,
		locker:  ir.locker,
	}
	log.Tracef(trace.Private, "Inversion of %s is %s", ir, retval)
	return &retval
}

// IsEmpty returns true if there is are allocated IDs.
func (ir IDRing) IsEmpty() bool {
	if ir.locker != nil {
		ir.locker.Lock()
		defer ir.locker.Unlock()
	}
	if len(ir.Ranges) > 1 {
		return false
	}
	r := ir.Ranges[0]
	return r.Min == ir.OrigMin && r.Max == ir.OrigMax
}

// GetID returns the first available ID, starting with OrigMin.
// It will return an IDRingOverflowError if no more IDs can be returned.
func (ir *IDRing) GetID() (uint64, error) {
	log.Tracef(trace.Inside, "GetID: Trying to get ID from %s", ir.String())
	if ir.locker != nil {
		ir.locker.Lock()
		defer ir.locker.Unlock()
	}
	if ir.Ranges == nil || len(ir.Ranges) == 0 {
		log.Tracef(trace.Inside, "GetID: Returning error, remaining %s", ir.String())
		return 0, IDRingOverflowError
	}
	retval := ir.Ranges[0].Min
	if retval == math.MaxUint64 || retval+1 > ir.Ranges[0].Max {
		// This range is exhausted, remove it...
		if len(ir.Ranges) == 1 {
			ir.Ranges = nil
		} else {
			ir.Ranges = ir.Ranges[1:]
		}
	} else {
		ir.Ranges[0].Min += 1
	}
	log.Tracef(trace.Inside, "GetID: Returning %d, remaining %s", retval, ir.String())
	return retval, nil
}

// ReclaimID returns and ID to the pool.
func (ir *IDRing) ReclaimID(id uint64) error {
	if ir.locker != nil {
		ir.locker.Lock()
		defer ir.locker.Unlock()
	}
	return ir.ReclaimIDNoLock(id)
}

// ReclaimIDs reclaims a list of IDs. If an error occurs, what
// additionally a list of IDs that could not be reclaimed is returned.
func (ir *IDRing) ReclaimIDs(ids []uint64) (error, []uint64) {
	// TODO this can be optimized for cases where ids are sequential.
	if ir.locker != nil {
		ir.locker.Lock()
		defer ir.locker.Unlock()
	}
	for idx, id := range ids {
		err := ir.ReclaimIDNoLock(id)
		if err != nil {
			return common.NewError("Could not reclaim ID %d at %d: %s", id, idx, err), ids[idx:]
		}
	}
	return nil, nil
}

// ReclaimIDNoLock returns the provided ID into the pool, so it can
// be returned again upon some future call to GetID.
func (idRing *IDRing) ReclaimIDNoLock(id uint64) error {
	if idRing.Ranges == nil || len(idRing.Ranges) == 0 {
		idRing.Ranges = []Range{Range{Min: id, Max: id}}
		log.Tracef(trace.Inside, "ReclaimID: Reclaimed ID %d to get %s", id, *idRing)
		return nil
	}
	if id < idRing.OrigMin || id > idRing.OrigMax {
		return common.NewError("Cannot reclaim %d as it is outside of range %d-%d", id, idRing.OrigMin, idRing.OrigMax)
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
			return common.NewError("ReclaimID: Cannot reclaim id %d: it has not been allocated and is part of range %d: %s", id, i, *idRing)
		}
	}

	if !done {
		// At this point this can only mean that the ID being
		// reclaimed is higher than the Max of the last range
		idRing.Ranges = append(idRing.Ranges, Range{Min: id, Max: id})
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
	//	log.Tracef(trace.Inside, "mergeRanges: Before: %s", *idRing)
	var changes bool
	for {
		changes = false
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
					newRanges := append(prevRanges, mergedRange)
					newRanges = append(newRanges, follRanges...)
					idRing.Ranges = newRanges
					changes = true
					//					log.Tracef(trace.Inside, "mergeRanges: %d, prevRanges %s, follRanges %s, newRanges %s", i, prevRanges, follRanges, newRanges)
					//					log.Tracef(trace.Inside, "mergeRanges: During %s", *idRing)
					break
				}
			}
		}
		if !changes {
			break
		}
	}
	//	log.Tracef(trace.Inside, "mergeRanges: After: %s", *idRing)
}
