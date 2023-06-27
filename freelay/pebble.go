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
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/manifoldfinance/mev-freelay/logger"
)

const (
	keySeparator = "_"

	validatorDBKey               = "validator"
	deliveredBlockHashDBKey      = "deliveredBlockHash"
	deliveredSlotDBKey           = "deliveredSlot"
	deliveredBlockNumberDBKey    = "deliveredBlockNumber"
	deliveredProposerPubkeyDBKey = "deliveredProposerPubkey"
	deliveredValueDBKey          = "deliveredValue"
	deliveredCoundDBKey          = "deliveredCount"
	submittedBlockHashDBKey      = "submittedBlockHash"
	submittedSlotDBKey           = "submittedSlot"
	submittedBlockNumberDBKey    = "submittedBlockNumber"
	submittedProposerPubkeyDBKey = "submittedProposerPubkey"
	missedDBKey                  = "missed"
	executedDBKey                = "executed"
	bidTraceDBKey                = "bidTrace"
	bestBidDBKey                 = "bestBid"
	builderDBKey                 = "builder"
	latestSlotDBKey              = "latestSlot"
)

var (
	maxInt64 = strings.Repeat("9", 32)
)

type pebbleDB struct {
	db    *pebble.DB
	flush bool
	log   logger.Logger
	pth   string
}

func NewPebbleDB(pth string, flush bool) (*pebbleDB, error) {
	opt := pebbleDBOpt()

	db, err := pebble.Open(pth, opt)
	if err != nil {
		return nil, err
	}

	log := logger.WithValues("module", "pebbleDB")

	p := &pebbleDB{
		db:    db,
		flush: flush,
		log:   log,
		pth:   pth,
	}

	if err := p.createDeliveredCount(); err != nil {
		log.Error(err, "failed to set delivered count")
		return nil, err
	}

	if err := p.createLatestSlot(); err != nil {
		log.Error(err, "failed to set latest slot")
		return nil, err
	}

	return p, nil
}

func (s *pebbleDB) Close() {
	if !s.flush {
		s.db.Flush() // nolint: errcheck
	}

	s.db.Close() // nolint: errcheck
}

func (s *pebbleDB) key(keys ...string) []byte {
	return []byte(strings.Join(keys, keySeparator))
}

func (s *pebbleDB) IsKnownBuilder(pubKey types.PublicKey) (bool, error) {
	value, closer, err := s.db.Get(s.key(builderDBKey, pubKey.String()))
	if err != nil {
		return false, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return false, ErrNoData
	}

	return true, nil
}

func (s *pebbleDB) InsertBlockBuilder(payload BlockBuilder) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return s.db.Set(s.key(builderDBKey, payload.BuilderPubkey.String()), b, pebble.Sync)
}

func (s *pebbleDB) Builder(pubKey types.PublicKey) (*BlockBuilder, error) {
	value, closer, err := s.db.Get(s.key(builderDBKey, pubKey.String()))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return nil, ErrNoData
	}

	var p BlockBuilder
	if err := json.Unmarshal(value, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

func (s *pebbleDB) Builders() ([]BlockBuilder, error) {
	it := s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(builderDBKey),
	})

	blockBuilders := make([]BlockBuilder, 0)
	it.First()
	for ; it.Valid(); it.Next() {
		k := string(it.Key())
		if !strings.HasPrefix(k, builderDBKey) {
			break
		}

		var v BlockBuilder
		if err := json.Unmarshal(it.Value(), &v); err != nil {
			it.Close() // nolint: errcheck
			return []BlockBuilder{}, err
		}
		blockBuilders = append(blockBuilders, v)
	}
	it.Close() // nolint: errcheck

	return blockBuilders, nil
}

func (s *pebbleDB) SetBuilderStatus(pubKey types.PublicKey, highPriority, blacklisted bool) error {
	db := s.db

	log := s.log.WithValues("method", "SetBuilderStatus", "pubKey", pubKey, "blacklisted", blacklisted, "highPriority", highPriority)

	key := s.key(builderDBKey, pubKey.String())
	value, closer, err := db.Get(key)
	if err != nil {
		log.Error(err, "failed to get block builder")
	} else {
		defer closer.Close() // nolint: errcheck
	}

	now := time.Now().UTC()

	var p BlockBuilder
	if value == nil {
		log = log.WithValues("action", "create")
		p = BlockBuilder{
			BuilderPubkey: pubKey,
			CreatedAt:     now,
			UpdatedAt:     now,
			Blacklisted:   blacklisted,
			HighPriority:  highPriority,
		}
	} else {
		log = log.WithValues("action", "update")
		if err := json.Unmarshal(value, &p); err != nil {
			return err
		}
		p.Blacklisted = blacklisted
		p.HighPriority = highPriority
		p.UpdatedAt = now
	}

	b, err := json.Marshal(p)
	if err != nil {
		return err
	}

	if err := db.Set(key, b, pebble.Sync); err != nil {
		return err
	}

	log.Debug("stored")
	return nil
}

// pubKey is BuilderPubKey
func (s *pebbleDB) UpsertBuilderSubmitted(pubKey types.PublicKey, slot uint64, submissionID string, simErr error) error {
	db := s.db

	log := s.log.WithValues("method", "UpsertBuilderSubmitted", "pubKey", pubKey, "slot", slot, "submissionID", submissionID, "simErr", simErr)

	key := s.key(builderDBKey, pubKey.String())
	value, closer, err := db.Get(key)
	if err != nil {
		log.Error(err, "failed to get block builder")
	} else {
		defer closer.Close() // nolint: errcheck
	}

	now := time.Now().UTC()

	var p BlockBuilder
	if value == nil {
		log = log.WithValues("action", "create")
		p = BlockBuilder{
			BuilderPubkey:       pubKey,
			LastSubmissionSlot:  slot,
			LastSubmissionID:    submissionID,
			NumSubmissionsTotal: 1,
			CreatedAt:           now,
			UpdatedAt:           now,
			FirstSubmissionAt:   now,
			LastSubmissionAt:    now,
			FirstSubmissionSlot: slot,
			FirstSubmissionID:   submissionID,
		}
	} else {
		log = log.WithValues("action", "update")
		if err := json.Unmarshal(value, &p); err != nil {
			return err
		}
		if p.NumSubmissionsTotal == 0 {
			p.FirstSubmissionSlot = slot
			p.FirstSubmissionID = submissionID
			p.FirstSubmissionAt = now
		}
		p.LastSubmissionSlot = slot
		p.LastSubmissionID = submissionID
		p.NumSubmissionsTotal++
		p.UpdatedAt = now
		p.LastSubmissionAt = now
	}

	if simErr != nil {
		p.NumSubmissionsSimFailed++
	}

	b, err := json.Marshal(p)
	if err != nil {
		return err
	}

	if err := db.Set(key, b, pebble.Sync); err != nil {
		return err
	}

	log.Debug("stored")
	return nil
}

// pubKey is BuilderPubKey
func (s *pebbleDB) UpsertBuilderDelivered(pubKey types.PublicKey, slot uint64, deliveredID string) error {
	db := s.db

	log := s.log.WithValues("method", "UpsertBlockBuilderDeliveredPayload", "pubKey", pubKey, "slot", slot, "deliveredID", deliveredID)

	key := s.key(builderDBKey, pubKey.String())
	value, closer, err := db.Get(key)
	if err != nil {
		log.Error(err, "failed to get block builder")
	} else {
		defer closer.Close() // nolint: errcheck
	}

	now := time.Now().UTC()

	var p BlockBuilder
	if value == nil {
		log = log.WithValues("action", "create")
		p = BlockBuilder{
			BuilderPubkey:      pubKey,
			LastDeliveredSlot:  slot,
			LastDeliveredID:    deliveredID,
			NumDeliveredTotal:  1,
			CreatedAt:          now,
			UpdatedAt:          now,
			FirstDeliveredAt:   now,
			LastDeliveredAt:    now,
			FirstDeliveredSlot: slot,
			FirstDeliveredID:   deliveredID,
		}
	} else {
		log = log.WithValues("action", "update")
		if err := json.Unmarshal(value, &p); err != nil {
			return err
		}
		if p.NumDeliveredTotal == 0 {
			p.FirstDeliveredSlot = slot
			p.FirstDeliveredID = deliveredID
			p.FirstDeliveredAt = now
		}
		p.LastDeliveredSlot = slot
		p.LastDeliveredID = deliveredID
		p.NumDeliveredTotal++
		p.UpdatedAt = now
		p.LastDeliveredAt = now
	}

	b, err := json.Marshal(p)
	if err != nil {
		return err
	}

	if err := db.Set(key, b, pebble.Sync); err != nil {
		return err
	}

	log.Debug("stored")
	return nil
}

func (s *pebbleDB) CountValidators() (uint64, error) {
	it := s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(validatorDBKey),
	})
	defer it.Close() // nolint: errcheck

	count := uint64(0)
	it.First()
	for ; it.Valid(); it.Next() {
		k := string(it.Key())
		if !strings.HasPrefix(k, validatorDBKey) {
			break
		}
		count++
	}

	return count, nil
}

func (s *pebbleDB) Validators() ([]types.SignedValidatorRegistration, error) {
	it := s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(validatorDBKey),
	})

	validators := make([]types.SignedValidatorRegistration, 0)
	it.First()
	for ; it.Valid(); it.Next() {
		k := string(it.Key())
		if !strings.HasPrefix(k, validatorDBKey) {
			break
		}

		var v SignedValidatorRegistrationExtended
		if err := json.Unmarshal(it.Value(), &v); err != nil {
			it.Close() // nolint: errcheck
			return []types.SignedValidatorRegistration{}, err
		}
		validators = append(validators, v.SignedValidatorRegistration)
	}
	it.Close() // nolint: errcheck

	return validators, nil
}

func (s *pebbleDB) PutValidator(pubKey types.PublicKey, payload SignedValidatorRegistrationExtended) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return s.db.Set(s.key(validatorDBKey, pubKey.String()), b, pebble.Sync)
}

func (s *pebbleDB) Validator(pubKey types.PublicKey) (*types.SignedValidatorRegistration, error) {
	value, closer, err := s.db.Get(s.key(validatorDBKey, pubKey.String()))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return nil, ErrNoData
	}

	var d SignedValidatorRegistrationExtended
	if err := json.Unmarshal(value, &d); err != nil {
		return nil, err
	}

	return &d.SignedValidatorRegistration, nil
}

func (s *pebbleDB) ValidatorExtended(pubKey types.PublicKey) (*SignedValidatorRegistrationExtended, error) {
	value, closer, err := s.db.Get(s.key(validatorDBKey, pubKey.String()))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return nil, ErrNoData
	}

	var p SignedValidatorRegistrationExtended
	if err := json.Unmarshal(value, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

func (s *pebbleDB) DeliveredCount() (uint64, error) {
	value, closer, err := s.db.Get(s.key(deliveredCoundDBKey))
	if err != nil {
		return 0, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return 0, ErrNoData
	}

	return byteArrayToInt[uint64](value), nil
}

func (s *pebbleDB) createLatestSlot() error {
	var slot uint64
	slotKey := s.key(latestSlotDBKey)

	db := s.db

	value, closer, err := db.Get(slotKey)
	if err == nil && value != nil {
		slot = byteArrayToInt[uint64](value)
		closer.Close() // nolint: errcheck
	}

	return db.Set(slotKey, intToByteArray(slot), pebble.Sync)
}

func (s *pebbleDB) SetLatestSlot(slot uint64) error {
	return s.db.Set(s.key(latestSlotDBKey), intToByteArray(slot), pebble.Sync)
}

func (s *pebbleDB) LatestSlot() (uint64, error) {
	value, closer, err := s.db.Get(s.key(latestSlotDBKey))
	if err != nil {
		return 0, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return 0, ErrNoData
	}

	return byteArrayToInt[uint64](value), nil
}

func (s *pebbleDB) createDeliveredCount() error {
	var count uint64
	countKey := s.key(deliveredCoundDBKey)

	db := s.db

	value, closer, err := db.Get(countKey)
	if err == nil && value != nil {
		count = byteArrayToInt[uint64](value)
		closer.Close() // nolint: errcheck
	}

	return db.Set(countKey, intToByteArray(count), pebble.Sync)
}

func (s *pebbleDB) increaseDeliveredCount() error {
	var count uint64
	countKey := s.key(deliveredCoundDBKey)

	db := s.db

	value, closer, err := db.Get(countKey)
	if err == nil && value != nil {
		count = byteArrayToInt[uint64](value)
		closer.Close() // nolint: errcheck
	}

	return db.Set(countKey, intToByteArray(count+1), pebble.Sync)
}

func (s *pebbleDB) PutDelivered(payload DeliveredPayload) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	batch := s.db.NewBatch()
	defer batch.Close() // nolint: errcheck

	blockHashKey := s.key(deliveredBlockHashDBKey, payload.BlockHash.String())
	if err := batch.Set(blockHashKey, b, pebble.Sync); err != nil {
		return err
	}

	blockNumberKey := s.key(deliveredBlockNumberDBKey, prefixKey(payload.BlockNumber), payload.BlockHash.String())
	if err := batch.Set(blockNumberKey, []byte{}, pebble.Sync); err != nil {
		return err
	}

	slotKey := s.key(deliveredSlotDBKey, prefixKey(payload.Slot), payload.BlockHash.String())
	if err := batch.Set(slotKey, []byte{}, pebble.Sync); err != nil {
		return err
	}

	proposerPubkeyKey := s.key(deliveredProposerPubkeyDBKey, payload.ProposerPubkey.String(), payload.BlockHash.String())
	if err := batch.Set(proposerPubkeyKey, []byte{}, pebble.Sync); err != nil {
		return err
	}

	valueKey := s.key(deliveredValueDBKey, prefixWithZeroAndLimit(payload.Value.BigInt(), 32), payload.BlockHash.String())
	if err := batch.Set(valueKey, intToByteArray(payload.Slot), pebble.Sync); err != nil {
		return err
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}

	log := s.log.WithValues("method", "PutDelivered", "blockHash", payload.BlockHash, "slot", payload.Slot, "proposerPubkey", payload.ProposerPubkey, "blockNumber", payload.BlockNumber)
	log.Debug("stored")
	if err := s.increaseDeliveredCount(); err != nil {
		log.Error(err, "failed to set delivered count")
	}

	return nil
}

func (s *pebbleDB) PutMissed(payload MissedPayload) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if err := s.db.Set(s.key(missedDBKey, prefixLongKey(payload.Slot, payload.ProposerPubkey.String(), payload.BlockHash.String())), b, pebble.Sync); err != nil {
		return err
	}

	s.log.Debug("PutMissed", "blockHash", payload.BlockHash, "slot", payload.Slot, "proposerPubkey", payload.ProposerPubkey, "blockHash", payload.BlockHash)

	return nil
}

func (s *pebbleDB) searchPayloadsUp(db *pebble.DB, key []byte, limit uint64) ([]string, error) {
	keyStr := string(key)
	n := uint64(0)
	hashes := make([]string, 0)

	it := db.NewIter(&pebble.IterOptions{
		LowerBound: key,
	})
	it.First()
	for ; it.Valid(); it.Next() {
		if n >= limit {
			break
		}

		k := string(it.Key())
		if !strings.HasPrefix(k, keyStr) {
			break
		}

		a := strings.Split(k, keySeparator)
		if len(a) != 3 {
			it.Close() // nolint: errcheck
			return []string{}, ErrInvalidKey
		}

		hashes = append(hashes, a[2])
		n++
	}
	it.Close() // nolint: errcheck

	return hashes, nil
}

func (s *pebbleDB) searchPayloadsDown(db *pebble.DB, keyUp, keyDown []byte, limit uint64) ([]string, error) {
	keyStr := string(keyDown)
	n := uint64(0)
	hashes, err := s.searchPayloadsUp(db, keyUp, limit)
	if err != nil {
		return []string{}, err
	}

	it := db.NewIter(&pebble.IterOptions{
		UpperBound: keyUp,
	})
	it.Last()
	for ; it.Valid(); it.Prev() {
		if n >= limit {
			break
		}

		k := string(it.Key())
		if !strings.HasPrefix(k, keyStr) {
			break
		}

		a := strings.Split(k, keySeparator)
		if len(a) != 3 {
			it.Close() // nolint: errcheck
			return []string{}, ErrInvalidKey
		}

		hashes = append(hashes, a[2])
		n++
	}
	it.Close() // nolint: errcheck

	return hashes, nil
}

func (s *pebbleDB) searchDeliveredPayloadsByCursorAndRewardUp(limit, cursor uint64) ([]string, error) {
	key := s.key(deliveredValueDBKey)
	keyStr := string(key)
	n := uint64(0)
	hashes := make([]string, 0)

	it := s.db.NewIter(&pebble.IterOptions{
		LowerBound: key,
	})
	it.First()
	for ; it.Valid(); it.Next() {
		if n >= limit {
			break
		}

		k := string(it.Key())
		if !strings.HasPrefix(k, keyStr) {
			break
		}

		a := strings.Split(k, keySeparator)
		if len(a) != 3 {
			it.Close() // nolint: errcheck
			return []string{}, ErrInvalidKey
		}

		// it.Value is slot number
		if byteArrayToInt[uint64](it.Value()) <= cursor {
			hashes = append(hashes, a[2])
			n++
		}
	}
	it.Close() // nolint: errcheck

	return hashes, nil
}

func (s *pebbleDB) searchDeliveredPayloadsByCursorAndRewardDown(limit, cursor uint64) ([]string, error) {
	key := s.key(deliveredValueDBKey)
	keyStr := string(key)
	n := uint64(0)
	hashes := make([]string, 0)

	it := s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(deliveredValueDBKey),
		UpperBound: s.key(deliveredValueDBKey, maxInt64),
	})
	it.Last()
	for ; it.Valid(); it.Prev() {
		if n >= limit {
			break
		}

		k := string(it.Key())
		if !strings.HasPrefix(k, keyStr) {
			break
		}

		a := strings.Split(k, keySeparator)
		if len(a) != 3 {
			it.Close() // nolint: errcheck
			return []string{}, ErrInvalidKey
		}

		// it.Value is slot number
		if byteArrayToInt[uint64](it.Value()) <= cursor {
			hashes = append(hashes, a[2])
			n++
		}
	}
	it.Close() // nolint: errcheck

	return hashes, nil
}

func (s *pebbleDB) Delivered(query ProposerPayloadQuery) ([]BidTraceReceived, error) {
	bidTraces := make([]BidTraceReceived, 0)

	if query.Limit == 0 {
		return bidTraces, nil
	}

	if query.BlockHash != (types.Hash{}) {
		key := s.key(deliveredBlockHashDBKey, query.BlockHash.String())
		v, closer, err := s.db.Get(key)
		if err != nil {
			return bidTraces, err
		}
		defer closer.Close() // nolint: errcheck

		if v == nil {
			return bidTraces, ErrNoData
		}

		var payload DeliveredPayload
		if err := json.Unmarshal(v, &payload); err != nil {
			return bidTraces, err
		}

		bidTraces = append(bidTraces, BidTraceReceived{
			BidTrace:    payload.BidTrace,
			Timestamp:   payload.Timestamp.Unix(),
			TimestampMs: payload.Timestamp.UnixMilli(),
		})

		return bidTraces, nil
	}

	hashes := make([]string, 0)
	limit := query.Limit
	q := 0

	if query.Slot != 0 {
		key := s.key(deliveredSlotDBKey, prefixKey(query.Slot))
		h, err := s.searchPayloadsDown(s.db, key, key, limit)
		if err != nil {
			return bidTraces, err
		}
		hashes = append(hashes, h...)
		q++
	} else if query.Cursor != 0 && query.OrderBy == 0 {
		keyUp := s.key(deliveredSlotDBKey, prefixKey(query.Cursor))
		keyDown := s.key(deliveredSlotDBKey)
		h, err := s.searchPayloadsDown(s.db, keyUp, keyDown, limit)
		if err != nil {
			return bidTraces, err
		}
		hashes = append(hashes, h...)
		q++
	} else if query.Cursor != 0 && query.OrderBy == -1 { // desc
		h, err := s.searchDeliveredPayloadsByCursorAndRewardDown(limit, query.Cursor)
		if err != nil {
			return bidTraces, err
		}
		hashes = append(hashes, h...)
		q++
	} else if query.Cursor != 0 && query.OrderBy == 1 { // asc
		h, err := s.searchDeliveredPayloadsByCursorAndRewardUp(limit, query.Cursor)
		if err != nil {
			return bidTraces, err
		}
		hashes = append(hashes, h...)
		q++
	}

	if query.BlockNumber != 0 {
		key := s.key(deliveredBlockNumberDBKey, prefixKey(query.BlockNumber))
		h, err := s.searchPayloadsDown(s.db, key, key, limit)
		if err != nil {
			return bidTraces, err
		}
		hashes = append(hashes, h...)
		q++
	}

	if query.ProposerPubkey != (types.PublicKey{}) {
		key := s.key(deliveredProposerPubkeyDBKey, query.ProposerPubkey.String())
		h, err := s.searchPayloadsDown(s.db, key, key, limit)
		if err != nil {
			return bidTraces, err
		}
		hashes = append(hashes, h...)
		q++
	}

	digests := make([]string, 0)
	if q == 0 && query.OrderBy == 0 {
		key := s.key(deliveredSlotDBKey)
		h, err := s.searchPayloadsDown(s.db, key, key, limit)
		if err != nil {
			return bidTraces, err
		}
		digests = append(digests, h...)
	} else if q == 0 && query.OrderBy == -1 { // desc
		h, err := s.searchDeliveredPayloadsByCursorAndRewardDown(limit, math.MaxUint64)
		if err != nil {
			return bidTraces, err
		}
		digests = append(digests, h...)
	} else if q == 0 && query.OrderBy == 1 { // asc
		h, err := s.searchDeliveredPayloadsByCursorAndRewardUp(limit, math.MaxUint64)
		if err != nil {
			return bidTraces, err
		}
		digests = append(digests, h...)
	} else {
		hashNum := make(map[string]int)
		for _, hash := range hashes {
			hashNum[hash]++
		}

		for hash, num := range hashNum {
			if num == q {
				digests = append(digests, hash)
			}
		}
	}

	for _, hash := range digests {
		value, closer, err := s.db.Get(s.key(deliveredBlockHashDBKey, hash))
		if err != nil {
			return bidTraces, err
		}
		if value == nil {
			closer.Close() // nolint: errcheck
			return bidTraces, ErrNoData
		}

		var v DeliveredPayload
		if err := json.Unmarshal(value, &v); err != nil {
			closer.Close() // nolint: errcheck
			return bidTraces, err
		}

		bidTraces = append(bidTraces, BidTraceReceived{
			BidTrace:    v.BidTrace,
			Timestamp:   v.Timestamp.Unix(),
			TimestampMs: v.Timestamp.UnixMilli(),
		})
		closer.Close() // nolint: errcheck
	}

	if query.OrderBy == -1 {
		sort.SliceStable(bidTraces, func(i, j int) bool {
			return bidTraces[i].Value.Cmp(&bidTraces[j].Value) == 1 // descending
		})
	} else if query.OrderBy == 1 {
		sort.SliceStable(bidTraces, func(i, j int) bool {
			return bidTraces[i].Value.Cmp(&bidTraces[j].Value) == -1 // ascending
		})
	} else {
		// == 0
		sort.SliceStable(bidTraces, func(i, j int) bool {
			return bidTraces[i].Slot > bidTraces[j].Slot // descending
		})
	}

	maxLimit := uint64(len(bidTraces))
	if maxLimit > query.Limit {
		maxLimit = query.Limit
	}

	return bidTraces[0:maxLimit], nil
}

func (s *pebbleDB) BidTrace(slot uint64, proposerPubKey types.PublicKey, blockHash types.Hash) (*BidTrace, error) {
	var bidTrace BidTrace

	value, closer, err := s.db.Get(s.key(bidTraceDBKey, prefixLongKey(slot, proposerPubKey.String(), blockHash.String())))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return nil, ErrNoPayloads
	}

	var btTime BidTraceTimestamp
	if err := json.Unmarshal(value, &btTime); err != nil {
		return nil, err
	}

	if time.Since(btTime.Timestamp) > expireBidTraceAfter {
		return nil, ErrBidTraceExpired
	}

	bidTrace = btTime.BidTrace

	return &bidTrace, nil
}

func (s *pebbleDB) Executed(slot uint64, proposerKey types.PublicKey, blockHash types.Hash) (*GetPayloadResponse, error) {
	var payload GetPayloadResponse

	value, closer, err := s.db.Get(s.key(executedDBKey, prefixLongKey(slot, proposerKey.String(), blockHash.String())))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return nil, ErrNoPayloads
	}

	var v VersionedExecutedPayload
	if err := json.Unmarshal(value, &v); err != nil {
		return nil, err
	}

	payload = GetPayloadResponse{
		Capella: v.Capella,
	}

	return &payload, nil
}

func (s *pebbleDB) PutSubmitted(payload BidTraceExtended) error {
	batch := s.db.NewBatch()
	defer batch.Close() // nolint: errcheck

	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	blockHashKey := s.key(submittedBlockHashDBKey, payload.BlockHash.String())
	if err := batch.Set(blockHashKey, b, pebble.Sync); err != nil {
		return err
	}

	blockNumberKey := s.key(submittedBlockNumberDBKey, prefixKey(payload.BlockNumber), payload.BlockHash.String())
	if err := batch.Set(blockNumberKey, []byte{}, pebble.Sync); err != nil {
		return err
	}

	slotKey := s.key(submittedSlotDBKey, prefixKey(payload.Slot), payload.BlockHash.String())
	if err := batch.Set(slotKey, []byte{}, pebble.Sync); err != nil {
		return err
	}

	proposerPubKey := s.key(submittedProposerPubkeyDBKey, payload.ProposerPubkey.String(), payload.BlockHash.String())
	if err := batch.Set(proposerPubKey, []byte{}, pebble.Sync); err != nil {
		return err
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}

	s.log.Debug("PutSubmitted", "slot", payload.Slot, "blockHash", payload.BlockHash, "blockNumber", payload.BlockNumber)

	return nil
}

func (s *pebbleDB) Submitted(query BuilderBlockQuery) ([]BidTraceReceived, error) {
	submissions := make([]BidTraceReceived, 0)

	if query.Limit == 0 {
		return submissions, nil
	}

	if query.BlockHash != (types.Hash{}) {
		key := s.key(submittedBlockHashDBKey, query.BlockHash.String())
		value, closer, err := s.db.Get(key)
		if err != nil {
			return submissions, err
		}
		defer closer.Close() // nolint: errcheck

		if value == nil {
			return submissions, ErrNoData
		}

		var v BidTraceExtended
		if err := json.Unmarshal(value, &v); err != nil {
			return submissions, err
		}

		submissions = append(submissions, BidTraceReceived{
			BidTrace:    v.BidTrace,
			Timestamp:   v.Timestamp.Unix(),
			TimestampMs: v.Timestamp.UnixMilli(),
		})

		return submissions, nil
	}

	hashes := make([]string, 0)
	limit := query.Limit
	q := 0

	if query.Slot != 0 {
		key := s.key(submittedSlotDBKey, prefixKey(query.Slot))
		h, err := s.searchPayloadsDown(s.db, key, key, limit)
		if err != nil {
			return submissions, err
		}
		hashes = append(hashes, h...)
		q++
	}

	if query.BlockNumber != 0 {
		key := s.key(submittedBlockNumberDBKey, prefixKey(query.BlockNumber))
		h, err := s.searchPayloadsDown(s.db, key, key, limit)
		if err != nil {
			return submissions, err
		}
		hashes = append(hashes, h...)
		q++
	}

	digests := make([]string, 0)
	if q == 0 {
		key := s.key(submittedSlotDBKey)
		h, err := s.searchPayloadsDown(s.db, key, key, limit)
		if err != nil {
			return submissions, err
		}
		digests = append(digests, h...)
	} else {
		hashNum := make(map[string]int)
		for _, hash := range hashes {
			hashNum[hash]++
		}

		for hash, num := range hashNum {
			if num == q {
				digests = append(digests, hash)
			}
		}
	}

	for _, hash := range digests {
		value, closer, err := s.db.Get(s.key(submittedBlockHashDBKey, hash))
		if err != nil {
			return submissions, err
		}
		if value == nil {
			closer.Close() // nolint: errcheck
			return submissions, ErrNoData
		}

		var v BidTraceExtended
		if err := json.Unmarshal(value, &v); err != nil {
			closer.Close() // nolint: errcheck
			return submissions, err
		}

		submissions = append(submissions, BidTraceReceived{
			BidTrace:    v.BidTrace,
			Timestamp:   v.Timestamp.Unix(),
			TimestampMs: v.Timestamp.UnixMilli(),
		})
		closer.Close() // nolint: errcheck
	}

	sort.SliceStable(submissions, func(i, j int) bool {
		return submissions[i].Slot > submissions[j].Slot // descending
	})

	maxLimit := uint64(len(submissions))
	if maxLimit > query.Limit {
		maxLimit = query.Limit
	}

	return submissions[0:maxLimit], nil
}

func (s *pebbleDB) PutBuilderBid(bidTrace BidTrace, getPayloadResponse GetPayloadResponse, getHeaderResponse GetHeaderResponse, receivedAt time.Time) error {
	db := s.db
	batch := db.NewBatch()
	defer batch.Close() // nolint: errcheck

	log := s.log.WithValues("method", "PutBuilderBid", "slot", bidTrace.Slot, "proposerPubkey", bidTrace.ProposerPubkey, "builderPubkey", bidTrace.BuilderPubkey, "parentHash", bidTrace.ParentHash)

	// bid trace
	b, err := json.Marshal(BidTraceTimestamp{
		BidTrace:  bidTrace,
		Timestamp: receivedAt,
	})
	if err != nil {
		return err
	}

	bidTraceKey := s.key(bidTraceDBKey, prefixLongKey(bidTrace.Slot, bidTrace.ProposerPubkey.String(), bidTrace.BlockHash.String()))
	if err := batch.Set(bidTraceKey, b, pebble.Sync); err != nil {
		return err
	}

	// executed payload
	b, err = json.Marshal(VersionedExecutedPayload{
		Capella:   getPayloadResponse.Capella,
		Timestamp: receivedAt,
	})
	if err != nil {
		return err
	}

	executionKey := s.key(executedDBKey, prefixLongKey(bidTrace.Slot, bidTrace.ProposerPubkey.String(), bidTrace.BlockHash.String()))
	if err := batch.Set(executionKey, b, pebble.Sync); err != nil {
		return err
	}

	// latest builder bid
	latestBuilderBid := BuilderBidHeaderResponse{
		Capella:   getHeaderResponse.Capella,
		Timestamp: receivedAt,
	}
	b, err = json.Marshal(latestBuilderBid)
	if err != nil {
		return err
	}

	headerBestBidKey := s.key(bestBidDBKey, prefixLongKey(bidTrace.Slot, bidTrace.ParentHash.String(), bidTrace.ProposerPubkey.String()))
	bestBid, closer, err := db.Get(headerBestBidKey)
	if err != nil {
		log.Error(err, "no best bid found", "key", headerBestBidKey)
	} else {
		defer closer.Close() // nolint: errcheck
	}

	updateBestBid := true
	if bestBid != nil {
		var bestBuilderBid BuilderBidHeaderResponse
		if err := json.Unmarshal(bestBid, &bestBuilderBid); err != nil {
			return err
		}

		if bestBuilderBid.Value().Cmp(latestBuilderBid.Value()) > 0 && time.Since(bestBuilderBid.Timestamp) <= expireBidAfter {
			updateBestBid = false
		}
	}

	if updateBestBid {
		if err := batch.Set(headerBestBidKey, b, pebble.Sync); err != nil {
			return err
		}
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}

	log.Debug("stored")

	return nil
}

func (s *pebbleDB) BestBid(slot uint64, parentHash, proposerKey string) (*GetHeaderResponse, error) {
	b, closer, err := s.db.Get(s.key(bestBidDBKey, prefixLongKey(slot, parentHash, proposerKey)))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if b == nil {
		return nil, ErrBestBidNotFound
	}

	var bid BuilderBidHeaderResponse
	if err := json.Unmarshal(b, &bid); err != nil {
		return nil, err
	}

	if time.Since(bid.Timestamp) > expireBidAfter {
		return nil, ErrBestBidExpired
	}

	payload := GetHeaderResponse{
		Capella: bid.Capella,
	}
	return &payload, nil
}

func (s *pebbleDB) submittedByBlockHash(blockHash string) (*BidTraceExtended, error) {
	value, closer, err := s.db.Get(s.key(submittedBlockHashDBKey, blockHash))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return nil, nil
	}

	var v BidTraceExtended
	if err := json.Unmarshal(value, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func (s *pebbleDB) executedByKey(key string) (*VersionedExecutedPayload, error) {
	value, closer, err := s.db.Get(s.key(executedDBKey, key))
	if err != nil {
		return nil, err
	}
	defer closer.Close() // nolint: errcheck

	if value == nil {
		return nil, nil
	}

	var v VersionedExecutedPayload
	if err := json.Unmarshal(value, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func (s *pebbleDB) Archive(tw *tar.Writer, w http.ResponseWriter, slot uint64) error {
	log := s.log.WithValues("method", "Archive", "slot", slot)

	it := s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(submittedSlotDBKey),
		UpperBound: s.key(submittedSlotDBKey, prefixKey(slot)),
	})
	defer it.Close() // nolint: errcheck

	it.Last()
	k := string(it.Key())
	if !strings.HasPrefix(k, submittedSlotDBKey) {
		it.Prev()
	}

	a := strings.Split(k, keySeparator)
	if len(a) != 3 {
		it.Close() // nolint: errcheck
		return ErrNoArchivePayloadsFound
	}

	to := a[1]
	it.First()
	k = string(it.Key())
	if !strings.HasPrefix(k, submittedSlotDBKey) {
		it.Next()
	}
	a = strings.Split(k, keySeparator)
	if len(a) != 3 {
		it.Close() // nolint: errcheck
		return ErrInvalidKey
	}
	from := a[1]

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=slot_%s_%s.tar", from, to))

	slots := make(map[string]struct{})

	it.First()
	for ; it.Valid(); it.Next() {
		k := string(it.Key())
		if !strings.HasPrefix(k, submittedSlotDBKey) {
			break
		}

		a := strings.Split(k, keySeparator)
		if len(a) != 3 {
			return ErrInvalidKey
		}

		sk := a[1]
		bh := a[2]

		bid, err := s.submittedByBlockHash(bh)
		if err != nil {
			log.Error(err, "failed to check submitted block hash", "blockHash", bh)
			continue
		}

		eparts := strings.Split(bid.ExecutionPayloadKey, "_")
		if len(eparts) != 3 {
			log.Error(errors.New("invalid execution payload key"), "invalid execution payload key", "key", bid.ExecutionPayloadKey)
			continue
		}

		archive := BidTraceArchived{
			Slot:                 bid.Slot,
			BuilderPubkey:        bid.BuilderPubkey,
			ProposerPubkey:       bid.ProposerPubkey,
			ProposerFeeRecipient: bid.ProposerFeeRecipient,
			Value:                bid.Value,
			Signature:            bid.Signature,
			Timestamp:            bid.Timestamp.UTC().Unix(),
			IP:                   bid.IP,
			SimError:             bid.SimError,
		}

		eProposerKey := eparts[1]
		eBlockHash := eparts[2]

		eid := fmt.Sprintf("%018d_%s_%s", bid.Slot, eProposerKey, eBlockHash)
		e, err := s.executedByKey(eid)
		if err != nil {
			log.Error(err, "failed to check executed payload", "key", eid)
		} else {
			archive.ExecutedPayload = &GetPayloadResponse{
				Capella: e.Capella,
			}
		}

		body, err := json.Marshal(archive)
		if err != nil {
			return err
		}

		// create a folder if it doesnt exist
		if _, ok := slots[sk]; !ok {
			slots[sk] = struct{}{}
			if err := tw.WriteHeader(&tar.Header{
				Name:     sk,
				Typeflag: tar.TypeDir,
				Mode:     0755,
				ModTime:  bid.Timestamp.UTC(),
			}); err != nil {
				return err
			}
		}

		// write the payload
		if err := tw.WriteHeader(&tar.Header{
			Name:    fmt.Sprintf("%s/%d_%s_%s.json", sk, archive.Timestamp, eProposerKey, eBlockHash),
			Mode:    0644,
			Size:    int64(len(body)),
			ModTime: bid.Timestamp.UTC(),
		}); err != nil {
			return err
		}
		if _, err := tw.Write(body); err != nil {
			return err
		}

	}

	return nil
}

func (s *pebbleDB) Prune(slot uint64) error {
	log := s.log.WithValues("method", "Prune", "slot", slot)

	// increase slot by 1 so we catch it with upper bound in iterator
	upper := slot + 1

	it := s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(submittedSlotDBKey),
		UpperBound: s.key(submittedSlotDBKey, prefixKey(upper)),
	})

	del := make(map[string]struct{})

	it.First()
	for ; it.Valid(); it.Next() {
		k := string(it.Key())
		if !strings.HasPrefix(k, submittedSlotDBKey) {
			break
		}

		a := strings.Split(k, keySeparator)
		if len(a) != 3 {
			it.Close() // nolint: errcheck
			return ErrInvalidKey
		}

		del[k] = struct{}{}

		bh := a[2]

		bid, err := s.submittedByBlockHash(bh)
		if err != nil {
			log.Error(err, "failed to get bid of block hash", "blockHash", bh)
			continue
		}

		del[string(s.key(submittedBlockHashDBKey, bh))] = struct{}{}
		del[string(s.key(submittedBlockNumberDBKey, prefixKey(bid.BlockNumber), bh))] = struct{}{}
		del[string(s.key(submittedProposerPubkeyDBKey, bid.ProposerPubkey.String(), bh))] = struct{}{}

	}
	it.Close() // nolint: errcheck

	it = s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(executedDBKey),
		UpperBound: s.key(executedDBKey, prefixKey(upper)),
	})

	it.First()
	for ; it.Valid(); it.Next() {
		k := string(it.Key())
		if !strings.HasPrefix(k, executedDBKey) {
			break
		}

		del[k] = struct{}{}
	}
	it.Close() // nolint: errcheck

	it = s.db.NewIter(&pebble.IterOptions{
		LowerBound: s.key(bidTraceDBKey),
		UpperBound: s.key(bidTraceDBKey, prefixKey(upper)),
	})

	it.First()
	for ; it.Valid(); it.Next() {
		k := string(it.Key())
		if !strings.HasPrefix(k, bidTraceDBKey) {
			break
		}

		del[k] = struct{}{}
	}
	it.Close() // nolint: errcheck

	batch := s.db.NewBatch()
	defer batch.Close() // nolint: errcheck

	for key := range del {
		if err := batch.Delete([]byte(key), pebble.Sync); err != nil {
			return err
		}
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}

	return nil
}

func (s *pebbleDB) clone(pth string) error {
	opt := pebbleDBOpt()
	db, err := pebble.Open(pth, opt)
	if err != nil {
		return err
	}
	defer db.Close() // nolint: errcheck
	defer db.Flush() // nolint: errcheck

	it := s.db.NewIter(nil)
	defer it.Close() // nolint: errcheck

	batch := db.NewBatch()
	num := 0

	it.First()
	for ; it.Valid(); it.Next() {
		if err := batch.Set(it.Key(), it.Value(), pebble.Sync); err != nil {
			return err
		}
		num++

		if num >= 1000 {
			if err := batch.Commit(pebble.Sync); err != nil {
				batch.Close() // nolint: errcheck
				return err
			}
			batch.Close() // nolint: errcheck
			batch = db.NewBatch()
			num = 0
		}
	}

	if num > 0 {
		if err := batch.Commit(pebble.Sync); err != nil {
			batch.Close() // nolint: errcheck
			return err
		}
		batch.Close() // nolint: errcheck
	}

	return nil
}

func (s *pebbleDB) Backup(tw *tar.Writer) error {
	pth := fmt.Sprintf("%s_backup", s.pth)

	if _, err := os.Stat(pth); err == nil {
		if err := os.RemoveAll(pth); err != nil {
			return err
		}
	}

	defer func() {
		if err := os.RemoveAll(pth); err != nil {
			s.log.Error(err, "failed to remove backup folder", "path", pth)
		}
	}()

	if err := s.clone(pth); err != nil {
		return err
	}

	// walk through every file in the folder
	if err := filepath.Walk(pth, func(file string, fi os.FileInfo, _ error) error {
		// generate tar header
		header, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return err
		}

		// Calculate the path relative to the base directory
		relPath, err := filepath.Rel(pth, file)
		if err != nil {
			return err
		}

		// must provide real name
		// (see https://golang.org/src/archive/tar/common.go?#L626)
		header.Name = filepath.ToSlash(relPath)

		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// if not a dir, write file content
		if !fi.IsDir() {
			data, err := os.Open(file)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func pebbleDBOpt() *pebble.Options {
	opt := &pebble.Options{
		MaxOpenFiles: 16,
		// MemTableSize:                1<<30 - 1, // Max 1 GB
		MemTableStopWritesThreshold: 2,
		// MaxConcurrentCompactions: func() int { return runtime.NumCPU() },
		Levels: []pebble.LevelOptions{
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
		},
	}
	opt.Experimental.ReadSamplingMultiplier = -1

	return opt
}
