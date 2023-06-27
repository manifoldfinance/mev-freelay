// Copyright (c) 2023 Manifold Finance, Inc.
// The Universal Permissive License (UPL), Version 1.0
// Subject to the condition set forth below, permission is hereby granted to any person obtaining a copy of this software, associated documentation and/or data (collectively the “Software”), free of charge and under any and all copyright rights in the Software, and any and all patent rights owned or freely licensable by each licensor hereunder covering either (i) the unmodified Software as contributed to or provided by such licensor, or (ii) the Larger Works (as defined below), to deal in both
// (a) the Software, and
// (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if one is included with the Software (each a “Larger Work” to which the Software is contributed by such licensors),
// without restriction, including without limitation the rights to copy, create derivative works of, display, perform, and distribute the Software and make, use, sell, offer for sale, import, export, have made, and have sold the Software and the Larger Work(s), and to sublicense the foregoing rights on either these or other terms.
// This license is subject to the following condition:
// The above copyright notice and either this complete permission notice or at a minimum a reference to the UPL must be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// This script ensures source code files have copyright license headers. See license.sh for more information.
package freelay

import (
	"sync"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/manifoldfinance/mev-freelay/logger"
	"go.uber.org/atomic"
)

const dutyStateTTL = DurationPerEpoch + time.Duration(10)*time.Second

type DutySetter interface {
	Set(duties []BuilderGetValidatorsResponseEntry, slot uint64)
	DutyGetter
}

type DutyGetter interface {
	All() []BuilderGetValidatorsResponseEntry
	BySlot(slot uint64) *BuilderGetValidatorsResponseEntry
	Slot() uint64
}

type dutyState struct {
	proposerDutiesSlot uint64
	proposerDutyMap    map[uint64]*ProposerDutyData
	mux                sync.RWMutex
}

type ProposerDutyData struct {
	BuilderGetValidatorsResponseEntry
	Timestamp time.Time
}

func NewDutyState() *dutyState {
	return &dutyState{
		proposerDutyMap: make(map[uint64]*ProposerDutyData),
	}
}

func (d *dutyState) All() []BuilderGetValidatorsResponseEntry {
	d.mux.RLock()
	defer d.mux.RUnlock()
	duties := make([]BuilderGetValidatorsResponseEntry, len(d.proposerDutyMap))

	i := 0
	for _, value := range d.proposerDutyMap {
		duties[i] = value.BuilderGetValidatorsResponseEntry
		i++
	}

	return duties
}

func (d *dutyState) Set(duties []BuilderGetValidatorsResponseEntry, slot uint64) {
	d.mux.Lock()
	defer d.mux.Unlock()

	now := time.Now().UTC()

	d.proposerDutiesSlot = slot

	dutyMap := make(map[uint64]*ProposerDutyData)

	// filter out old duties
	r := 0
	for slot, duty := range d.proposerDutyMap {
		if duty.Timestamp.Add(dutyStateTTL).After(now) {
			dutyMap[slot] = duty
			continue
		}
		r++
	}

	logger.Info("removed old duties requests", "count", r)

	for _, duty := range duties {
		dutyMap[duty.Slot] = &ProposerDutyData{
			BuilderGetValidatorsResponseEntry: duty,
			Timestamp:                         now,
		}
	}

	d.proposerDutyMap = dutyMap
	logger.Info("set duties requests", "count", len(dutyMap), "headSlot", slot)
}

func (d *dutyState) BySlot(slot uint64) *BuilderGetValidatorsResponseEntry {
	d.mux.RLock()
	defer d.mux.RUnlock()
	// we do this because defer is called before the return so we might unlock the mux to early
	v := d.proposerDutyMap[slot]
	if v == nil {
		return nil
	}
	return &v.BuilderGetValidatorsResponseEntry
}

func (d *dutyState) Slot() uint64 {
	d.mux.RLock()
	defer d.mux.RUnlock()
	v := d.proposerDutiesSlot
	return v
}

type KnownValidatorSetter interface {
	Set(v map[types.PubkeyHex]uint64, vByIndx map[uint64]types.PubkeyHex, slot uint64)
	Updated(bool)
	KnownValidatorGetter
}

type KnownValidatorGetter interface {
	ByIndex(index uint64) (types.PubkeyHex, error)
	IsKnown(pbHex types.PubkeyHex) bool
	Count() uint64
	LastSlot() uint64
	IsUpdated() bool
}

type knownValidators struct {
	mux                    sync.RWMutex
	knownValidators        map[types.PubkeyHex]uint64
	knownValidatorsByIndex map[uint64]types.PubkeyHex
	lastSlot               uint64
	updated                atomic.Bool
}

func NewKnownValidators() *knownValidators {
	return &knownValidators{
		knownValidators:        make(map[types.PubkeyHex]uint64),
		knownValidatorsByIndex: make(map[uint64]types.PubkeyHex),
	}
}

func (vs *knownValidators) Set(v map[types.PubkeyHex]uint64, vByIndx map[uint64]types.PubkeyHex, slot uint64) {
	vs.mux.Lock()
	defer vs.mux.Unlock()
	vs.knownValidators = v
	vs.knownValidatorsByIndex = vByIndx
	vs.lastSlot = slot
}

func (vs *knownValidators) ByIndex(index uint64) (types.PubkeyHex, error) {
	vs.mux.RLock()
	defer vs.mux.RUnlock()
	v, ok := vs.knownValidatorsByIndex[index]
	if !ok {
		return "", ErrUnknownValidatorByIndx
	}

	return v, nil
}

func (vs *knownValidators) IsKnown(pbHex types.PubkeyHex) bool {
	vs.mux.RLock()
	defer vs.mux.RUnlock()
	_, ok := vs.knownValidators[pbHex]
	return ok
}

func (vs *knownValidators) Count() uint64 {
	vs.mux.RLock()
	defer vs.mux.RUnlock()
	count := uint64(len(vs.knownValidators))
	return count
}

func (vs *knownValidators) LastSlot() uint64 {
	vs.mux.RLock()
	defer vs.mux.RUnlock()
	return vs.lastSlot
}

func (vs *knownValidators) Updated(state bool) {
	vs.updated.Store(state)
}

func (vs *knownValidators) IsUpdated() bool {
	return vs.updated.Load()
}
