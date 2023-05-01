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
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/draganm/bolted"
	"github.com/draganm/bolted/dbpath"
	"github.com/draganm/bolted/embedded"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/manifoldfinance/mev-freelay/logger"
	"go.etcd.io/bbolt"
)

const (
	storeDBPth = "store.db"
)

var (
	validatorMapPth                      = dbpath.ToPath("validator")
	headerBestBidMapPth                  = dbpath.ToPath("header_best_bid_payload")           // top bids = max profit = best bid
	headerBidBuilderMapPth               = dbpath.ToPath("header_bid_builder")                // latest bids
	payloadDeliveredBlockHashMapPth      = dbpath.ToPath("payload_delivered_block_hash")      // delivered payloads - holds delivered payload
	payloadDeliveredSlotMapPth           = dbpath.ToPath("payload_delivered_slot")            // delivered payloads - holds blockhash
	payloadDeliveredProposerPubkeyMapPth = dbpath.ToPath("payload_delivered_proposer_pubkey") // delivered payloads - holds blockhash
	payloadDeliveredBlockNumberMapPth    = dbpath.ToPath("payload_delivered_block_number")    // delivered payloads - holds blockhash
	payloadDeliveredValueMapPth          = dbpath.ToPath("payload_delivered_value")           // delivered payloads - holds [blockhash/slot]
	payloadMissedMapPth                  = dbpath.ToPath("payload_missed")                    // delivered payloads - holds delivered payload
	payloadExecutedMapPth                = dbpath.ToPath("payload_executed")                  // executed payloads
	payloadSubmissionsBlockHashMapPth    = dbpath.ToPath("payload_submissions_block_hash")    // payload submissions - block builder submissions - holds submission payload
	payloadSubmissionsSlotMapPth         = dbpath.ToPath("payload_submissions_slot")          // payload submissions - block builder submissions - holds blockhash
	payloadSubmissionsBlockNumberMapPth  = dbpath.ToPath("payload_submissions_block_number")  // payload submissions - block builder submissions - holds blockhash
	bidTraceMapPth                       = dbpath.ToPath("bid_trace")                         // bid trace - block builder submissions
	statsMapPth                          = dbpath.ToPath("stats")                             // stats for the slots
	blockBuilderMapPth                   = dbpath.ToPath("block_builder")                     // block builder
	acceptNewBlockBuildersPth            = dbpath.ToPath("accept_new_block_builders")         // accept new block builders

	latestSlotKey             = "latest_slot"
	latestDeliveredSlotKey    = "latest_delivered_slot"
	activeValidatorPubkeysKey = "active_validator_pubkeys"

	expireBidAfter = 45 * time.Second
)

type StoreSetter interface {
	RejectNewBlockBuilders() error
	AcceptNewBlockBuilders() error
	SetBlockBuilderStatus(pubKey types.PublicKey, highPriority, blacklisted bool) error
	UpsertBlockBuilderSubmissionPayload(pubKey types.PublicKey, slot uint64, submissionID string, simErr error) error
	UpsertBlockBuilderDeliveredPayload(pubKey types.PublicKey, slot uint64, deliveredID string) error
	SetLatestSlotStats(headSlot uint64) error
	SetLatestDeliveredSlotStats(slot uint64) error
	SetActiveValidatorsStats(pubKeys []types.PublicKey) error
	PutRegistrationValidator(pubKey types.PublicKey, payload SignedValidatorRegistrationExtended) error
	PutDeliveredPayload(payload DeliveredPayload) error
	PutMissedPayload(slot uint64, proposerKey types.PublicKey, blockHash types.Hash, missed MissedPayload) error
	PutExecutedPayload(slot uint64, proposerKey types.PublicKey, blockHash types.Hash, payload VersionedExecutedPayload) error
	PutBuilderBlockSubmissionsPayload(payload BidTraceExtended) error
	PutBidTrace(bidTrace BidTraceTimestamp) error
	PutLatestBuilderBid(slot uint64, parentHash types.Hash, proposerKey, builderKey types.PublicKey, payload BuilderBidHeaderResponse) error
	UpdateBestBid(slot uint64, parentHash types.Hash, proposerKey types.PublicKey) error
	Close()
	StoreGetter
}

type StoreGetter interface {
	AreNewBlockBuildersAccepted() (bool, error)
	IsKnownBlockBuilder(pubKey types.PublicKey) (bool, error)
	BlockBuilder(pubKey types.PublicKey) (*BlockBuilder, error)
	AllBlockBuilders() ([]BlockBuilder, error)
	LatestSlotStats() (uint64, error)
	ActiveValidatorsStats() ([]types.PublicKey, error)
	AllRegisteredValidators() ([]types.SignedValidatorRegistration, error)
	RegisteredValidator(pubKey types.PublicKey) (*types.SignedValidatorRegistration, error)
	DeliveredPayloads(query ProposerPayloadQuery) ([]BidTraceReceived, error)
	DeliveredPayloadsCount() (uint64, error)
	ExecutedPayload(slot uint64, proposerKey types.PublicKey, blockHash types.Hash) (*GetPayloadResponse, error)
	BlockSubmissionsPayload(query BuilderBlockQuery) ([]BidTraceReceived, error)
	BidTrace(slot uint64, proposerKey types.PublicKey, blockHash types.Hash) (*BidTrace, error)
	LatestBuilderBid(slot uint64, parentHash types.Hash, proposerKey, builderKey types.PublicKey) (*BuilderBidHeaderResponse, error)
	LatestDeliveredSlotStats() (uint64, error)
	BestBid(slot uint64, parentHash types.Hash, proposerKey types.PublicKey) (*GetHeaderResponse, error)
	DB() bolted.Database
}

type store struct {
	db bolted.Database
}

func NewStore(prefix string) (*store, error) {
	dbPth := joinDBPth(prefix, storeDBPth)

	db, err := createStore(dbPth, []dbpath.Path{
		validatorMapPth,
		payloadDeliveredBlockHashMapPth,
		payloadDeliveredSlotMapPth,
		payloadDeliveredProposerPubkeyMapPth,
		payloadDeliveredBlockNumberMapPth,
		payloadDeliveredValueMapPth,
		payloadMissedMapPth,
		payloadExecutedMapPth,
		payloadSubmissionsBlockHashMapPth,
		payloadSubmissionsSlotMapPth,
		payloadSubmissionsBlockNumberMapPth,
		bidTraceMapPth,
		blockBuilderMapPth,
		statsMapPth,
		headerBestBidMapPth,
		headerBidBuilderMapPth,
	})
	if err != nil {
		return nil, err
	}

	return &store{
		db: db,
	}, nil
}

func (s *store) Close() {
	if err := s.db.Close(); err != nil {
		logger.Error(err, "failed to close store")
	}
}

func (s *store) DB() bolted.Database {
	return s.db
}

func (s *store) RejectNewBlockBuilders() error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		tx.Put(acceptNewBlockBuildersPth, intToByteArray[int64](0))
		return nil
	})
}

func (s *store) AcceptNewBlockBuilders() error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		tx.Put(acceptNewBlockBuildersPth, intToByteArray[int64](1))
		return nil
	})
}

func (s *store) AreNewBlockBuildersAccepted() (bool, error) {
	var accepted bool
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(acceptNewBlockBuildersPth)
		accepted = byteArrayToInt[int64](b) == 1
		return nil
	}); err != nil {
		return true, err
	}
	return accepted, nil
}

func (s *store) IsKnownBlockBuilder(pubKey types.PublicKey) (bool, error) {
	var exists bool
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		exists = tx.Exists(blockBuilderMapPth.Append(pubKey.String()))
		return nil
	}); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *store) BlockBuilder(pubKey types.PublicKey) (*BlockBuilder, error) {
	var payload BlockBuilder
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(blockBuilderMapPth.Append(pubKey.String()))
		err := json.Unmarshal(b, &payload)
		return err
	}); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (s *store) AllBlockBuilders() ([]BlockBuilder, error) {
	blockBuilders := make([]BlockBuilder, 0)
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(blockBuilderMapPth); !it.IsDone(); it.Next() {
			var bb BlockBuilder
			if err := json.Unmarshal(it.GetValue(), &bb); err != nil {
				return err
			}
			blockBuilders = append(blockBuilders, bb)
		}
		return nil
	}); err != nil {
		return []BlockBuilder{}, err
	}
	return blockBuilders, nil
}

func (s *store) SetBlockBuilderStatus(pubKey types.PublicKey, highPriority, blacklisted bool) error {
	if err := bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		var payload BlockBuilder
		now := time.Now().UTC()
		if tx.Exists(blockBuilderMapPth.Append(pubKey.String())) {
			bb := tx.Get(blockBuilderMapPth.Append(pubKey.String()))
			if err := json.Unmarshal(bb, &payload); err != nil {
				return err
			}
			payload.Blacklisted = blacklisted
			payload.HighPriority = highPriority
			payload.UpdatedAt = now
		} else {
			payload = BlockBuilder{
				BuilderPubkey: pubKey,
				CreatedAt:     now,
				UpdatedAt:     now,
				Blacklisted:   blacklisted,
				HighPriority:  highPriority,
			}
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		tx.Put(blockBuilderMapPth.Append(pubKey.String()), b)
		logger.Debug("SetBlockBuilderStatus", "pubkey", pubKey, "blacklisted", blacklisted, "highPriority", highPriority)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// pubKey is BuilderPubKey
func (s *store) UpsertBlockBuilderSubmissionPayload(pubKey types.PublicKey, slot uint64, submissionID string, simErr error) error {
	if err := bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		var payload BlockBuilder
		now := time.Now().UTC()
		if tx.Exists(blockBuilderMapPth.Append(pubKey.String())) {
			b := tx.Get(blockBuilderMapPth.Append(pubKey.String()))
			err := json.Unmarshal(b, &payload)
			if err != nil {
				return err
			}
			if payload.NumSubmissionsTotal == 0 {
				payload.FirstSubmissionSlot = slot
				payload.FirstSubmissionID = submissionID
				payload.FirstSubmissionAt = now
			}
			payload.LastSubmissionSlot = slot
			payload.LastSubmissionID = submissionID
			payload.NumSubmissionsTotal++
			payload.UpdatedAt = now
			payload.LastSubmissionAt = now
		} else {
			payload = BlockBuilder{
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
		}

		if simErr != nil {
			payload.NumSubmissionsSimFailed++
		}

		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		tx.Put(blockBuilderMapPth.Append(pubKey.String()), b)
		logger.Debug("UpsertBlockBuilderSubmissionPayload", "pubkey", pubKey, "slot", slot, "submissionID", submissionID, "simErr", simErr)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// pubKey is BuilderPubKey
func (s *store) UpsertBlockBuilderDeliveredPayload(pubKey types.PublicKey, slot uint64, deliveredID string) error {
	if err := bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		var payload BlockBuilder
		now := time.Now().UTC()
		if tx.Exists(blockBuilderMapPth.Append(pubKey.String())) {
			b := tx.Get(blockBuilderMapPth.Append(pubKey.String()))
			err := json.Unmarshal(b, &payload)
			if err != nil {
				return err
			}
			if payload.NumDeliveredTotal == 0 {
				payload.FirstDeliveredSlot = slot
				payload.FirstDeliveredID = deliveredID
				payload.FirstDeliveredAt = now
			}
			payload.LastDeliveredSlot = slot
			payload.LastDeliveredID = deliveredID
			payload.NumDeliveredTotal++
			payload.UpdatedAt = now
			payload.LastDeliveredAt = now
		} else {
			payload = BlockBuilder{
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
		}

		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		tx.Put(blockBuilderMapPth.Append(pubKey.String()), b)
		logger.Debug("UpsertBlockBuilderDeliveredPayload", "pubKey", pubKey, "slot", slot, "deliveredID", deliveredID)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (s *store) LatestSlotStats() (uint64, error) {
	var stats uint64
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(statsMapPth.Append(latestSlotKey))
		stats = byteArrayToInt[uint64](b)
		return nil
	}); err != nil {
		return 0, err
	}
	return stats, nil
}

func (s *store) SetLatestSlotStats(headSlot uint64) error {
	if err := bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		tx.Put(statsMapPth.Append(latestSlotKey), intToByteArray(headSlot))
		logger.Debug("SetLatestSlotStats", "headSlot", headSlot)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (s *store) SetLatestDeliveredSlotStats(slot uint64) error {
	if err := bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		tx.Put(statsMapPth.Append(latestDeliveredSlotKey), intToByteArray(slot))
		logger.Debug("SetLatestDeliveredSlotStats", "slot", slot)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (s *store) LatestDeliveredSlotStats() (uint64, error) {
	var stats uint64
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(statsMapPth.Append(latestDeliveredSlotKey))
		stats = byteArrayToInt[uint64](b)
		return nil
	}); err != nil {
		return 0, err
	}
	return stats, nil
}

func (s *store) SetActiveValidatorsStats(pubKeys []types.PublicKey) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		pubStr := joinPubKeys(pubKeys, ",")
		tx.Put(statsMapPth.Append(activeValidatorPubkeysKey), []byte(pubStr))
		logger.Debug("SetActiveValidatorsStats", "count", len(pubKeys))
		return nil
	})
}

func (s *store) ActiveValidatorsStats() ([]types.PublicKey, error) {
	var pbKeys []types.PublicKey
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		if !tx.Exists(statsMapPth.Append(activeValidatorPubkeysKey)) {
			return nil
		}
		b := tx.Get(statsMapPth.Append(activeValidatorPubkeysKey))
		pubKeys := strings.Split(string(b), ",")
		for _, pubKey := range pubKeys {
			var pbKey types.PublicKey
			if err := pbKey.UnmarshalText([]byte(pubKey)); err != nil {
				return err
			}
			pbKeys = append(pbKeys, pbKey)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return pbKeys, nil
}

func (s *store) AllRegisteredValidators() ([]types.SignedValidatorRegistration, error) {
	validators := make([]types.SignedValidatorRegistration, 0)
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(validatorMapPth); !it.IsDone(); it.Next() {
			var validator SignedValidatorRegistrationExtended
			if err := json.Unmarshal(it.GetValue(), &validator); err != nil {
				return err
			}
			validators = append(validators, validator.SignedValidatorRegistration)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return validators, nil
}

func (s *store) PutRegistrationValidator(pubKey types.PublicKey, payload SignedValidatorRegistrationExtended) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		tx.Put(validatorMapPth.Append(pubKey.String()), b)
		logger.Debug("PutRegistrationValidator", "pubKey", pubKey)
		return nil
	})
}

func (s *store) RegisteredValidator(pubKey types.PublicKey) (*types.SignedValidatorRegistration, error) {
	var payload types.SignedValidatorRegistration
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		var d SignedValidatorRegistrationExtended
		b := tx.Get(validatorMapPth.Append(pubKey.String()))
		err := json.Unmarshal(b, &d)
		payload = d.SignedValidatorRegistration
		return err
	}); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (s *store) PutDeliveredPayload(payload DeliveredPayload) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		blockHashPth := payloadDeliveredBlockHashMapPth.Append(payload.BlockHash.String())
		tx.Put(blockHashPth, b)

		blockNumberPth := payloadDeliveredBlockNumberMapPth.Append(prefixKey(payload.BlockNumber))
		if !tx.Exists(blockNumberPth) {
			tx.CreateMap(blockNumberPth)
		}
		tx.Put(blockNumberPth.Append(payload.BlockHash.String()), []byte{})

		slotPth := payloadDeliveredSlotMapPth.Append(prefixKey(payload.Slot))
		if !tx.Exists(slotPth) {
			tx.CreateMap(slotPth)
		}
		tx.Put(slotPth.Append(payload.BlockHash.String()), []byte{})

		proposerPubkeyPth := payloadDeliveredProposerPubkeyMapPth.Append(payload.ProposerPubkey.String())
		if !tx.Exists(proposerPubkeyPth) {
			tx.CreateMap(proposerPubkeyPth)
		}
		tx.Put(proposerPubkeyPth.Append(payload.BlockHash.String()), []byte{})

		valuePth := payloadDeliveredValueMapPth.Append(prefixWithZeroAndLimit(payload.Value.BigInt(), 32))
		if !tx.Exists(valuePth) {
			tx.CreateMap(valuePth)
		}
		tx.Put(valuePth.Append(payload.BlockHash.String()), intToByteArray(payload.Slot))

		logger.Debug("PutDeliveredPayload", "blockHash", payload.BlockHash, "slot", payload.Slot, "proposerPubkey", payload.ProposerPubkey, "blockNumber", payload.BlockNumber)
		return nil
	})
}

func (s *store) DeliveredPayloads(query ProposerPayloadQuery) ([]BidTraceReceived, error) {
	bidTraces := make([]BidTraceReceived, 0)

	if query.Limit == 0 {
		return bidTraces, nil
	}

	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		// cursor is get all the slots that are smaller or equal cursor
		if (query.BlockHash != types.Hash{}) {
			pth := payloadDeliveredBlockHashMapPth.Append(query.BlockHash.String())
			if !tx.Exists(pth) {
				return nil
			}
			var payload DeliveredPayload
			b := tx.Get(pth)
			if err := json.Unmarshal(b, &payload); err != nil {
				return err
			}

			bidTraces = append(bidTraces, BidTraceReceived{
				BidTrace:    payload.BidTrace,
				Timestamp:   payload.Timestamp.Unix(),
				TimestampMs: payload.Timestamp.UnixMilli(),
			})
			return nil
		}

		num := 0
		blockHashes := make([]string, 0)
		if query.Slot != 0 {
			pth := payloadDeliveredSlotMapPth.Append(prefixKey(query.Slot))
			if !tx.Exists(pth) {
				return nil
			}
			for it := tx.Iterator(pth); !it.IsDone(); it.Next() {
				blockHash := it.GetKey()
				blockHashes = append(blockHashes, blockHash)
			}
			num++
		} else if query.Cursor != 0 {
			var i uint64 = 0
			limit := query.Limit

			if query.OrderBy == -1 { // descending order of values
				it := tx.Iterator(payloadDeliveredValueMapPth)
				it.Last()
				for ; !it.IsDone(); it.Prev() {
					if i >= limit {
						break
					}
					for it2 := tx.Iterator(payloadDeliveredValueMapPth.Append(it.GetKey())); !it2.IsDone(); it2.Next() {
						if i >= limit {
							break
						}
						value := byteArrayToInt[uint64](it2.GetValue())
						if value <= query.Cursor {
							blockHash := it2.GetKey()
							blockHashes = append(blockHashes, blockHash)
							i++
						}
					}
				}
			} else if query.OrderBy == 1 { // ascending order of values
				it := tx.Iterator(payloadDeliveredValueMapPth)
				for ; !it.IsDone(); it.Next() {
					if i >= limit {
						break
					}
					for it2 := tx.Iterator(payloadDeliveredValueMapPth.Append(it.GetKey())); !it2.IsDone(); it2.Next() {
						if i >= limit {
							break
						}
						value := byteArrayToInt[uint64](it2.GetValue())
						if value <= query.Cursor {
							blockHash := it2.GetKey()
							blockHashes = append(blockHashes, blockHash)
							i++
						}
					}
				}
			} else { // sort by slot number
				it := tx.Iterator(payloadDeliveredSlotMapPth)
				findKey := prefixKey(query.Cursor)
				it.Seek(findKey)
				if it.GetKey() != findKey {
					it.Prev()
				}
				for ; !it.IsDone(); it.Prev() {
					if i >= limit {
						break
					}

					for it2 := tx.Iterator(payloadDeliveredSlotMapPth.Append(it.GetKey())); !it2.IsDone(); it2.Next() {
						if i >= limit {
							break
						}
						blockHash := it2.GetKey()
						blockHashes = append(blockHashes, blockHash)
						i++
					}
				}
			}
			num++
		}

		if query.BlockNumber != 0 {
			pth := payloadDeliveredBlockNumberMapPth.Append(prefixKey(query.BlockNumber))
			if !tx.Exists(pth) {
				return nil
			}
			for it := tx.Iterator(pth); !it.IsDone(); it.Next() {
				blockHash := it.GetKey()
				blockHashes = append(blockHashes, blockHash)
			}
			num++
		}

		if (query.ProposerPubkey != types.PublicKey{}) {
			pth := payloadDeliveredProposerPubkeyMapPth.Append(query.ProposerPubkey.String())
			if !tx.Exists(pth) {
				return nil
			}
			for it := tx.Iterator(pth); !it.IsDone(); it.Next() {
				blockHash := it.GetKey()
				blockHashes = append(blockHashes, blockHash)
			}
			num++
		}

		searchBlockHashes := make([]string, 0)
		if num == 0 && query.OrderBy == 0 { // sort by slot number
			it := tx.Iterator(payloadDeliveredSlotMapPth)
			it.Last()
			var i uint64 = 0
			limit := query.Limit
			for ; !it.IsDone(); it.Prev() {
				if i >= limit {
					break
				}
				for it2 := tx.Iterator(payloadDeliveredSlotMapPth.Append(it.GetKey())); !it2.IsDone(); it2.Next() {
					if i >= limit {
						break
					}
					blockHash := it2.GetKey()
					searchBlockHashes = append(searchBlockHashes, blockHash)
					i++
				}
			}
		} else if num == 0 && query.OrderBy == -1 { // descending order of value
			it := tx.Iterator(payloadDeliveredValueMapPth)
			it.Last()
			var i uint64 = 0
			limit := query.Limit
			logger.Debug("DeliveredPayloads", "it", it.GetKey(), "limit", limit)
			for ; !it.IsDone(); it.Prev() {
				if i >= limit {
					break
				}

				for it2 := tx.Iterator(payloadDeliveredValueMapPth.Append(it.GetKey())); !it2.IsDone(); it2.Next() {
					if i >= limit {
						break
					}
					blockHash := it2.GetKey()
					searchBlockHashes = append(searchBlockHashes, blockHash)
					i++
				}
			}
		} else if num == 0 && query.OrderBy == 1 { // ascending order of value
			it := tx.Iterator(payloadDeliveredValueMapPth)
			var i uint64 = 0
			limit := query.Limit
			for ; !it.IsDone(); it.Next() {
				if i >= limit {
					break
				}

				for it2 := tx.Iterator(payloadDeliveredValueMapPth.Append(it.GetKey())); !it2.IsDone(); it2.Next() {
					if i >= limit {
						break
					}
					blockHash := it2.GetKey()
					searchBlockHashes = append(searchBlockHashes, blockHash)
					i++
				}
			}
		} else {
			blockHashNum := make(map[string]int)
			for _, blockHash := range blockHashes {
				blockHashNum[blockHash]++
			}

			for blockHash, n := range blockHashNum {
				if n != num {
					continue
				}
				searchBlockHashes = append(searchBlockHashes, blockHash)
			}
		}

		for _, blockHash := range searchBlockHashes {
			if !tx.Exists(payloadDeliveredBlockHashMapPth.Append(blockHash)) {
				continue
			}
			var payload DeliveredPayload
			b := tx.Get(payloadDeliveredBlockHashMapPth.Append(blockHash))
			if err := json.Unmarshal(b, &payload); err != nil {
				return err
			}
			bidTraces = append(bidTraces, BidTraceReceived{
				BidTrace:    payload.BidTrace,
				Timestamp:   payload.Timestamp.Unix(),
				TimestampMs: payload.Timestamp.UnixMilli(),
			})
		}
		return nil
	}); err != nil {
		return nil, err
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

	limit := uint64(len(bidTraces))
	if limit > query.Limit {
		limit = query.Limit
	}

	return bidTraces[0:limit], nil
}

func (s *store) PutMissedPayload(slot uint64, proposerKey types.PublicKey, blockHash types.Hash, missed MissedPayload) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(missed)
		if err != nil {
			return err
		}

		tx.Put(payloadMissedMapPth.Append(prefixLongKey(slot, proposerKey.String(), blockHash.String())), b)
		logger.Debug("PutMissedPayload", "slot", slot, "proposerPubkey", proposerKey, "blockHash", blockHash)

		return nil
	})
}

func (s *store) LastDeliveredSlot() (uint64, error) {
	var slot uint64
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		it := tx.Iterator(payloadDeliveredSlotMapPth)
		it.Last()
		if it.IsDone() {
			return nil
		}
		num, err := strconv.ParseUint(it.GetKey(), 10, 64)
		if err != nil {
			return err
		}
		slot = num
		return nil
	}); err != nil {
		return 0, err
	}
	return slot, nil
}

func (s *store) DeliveredPayloadsCount() (uint64, error) {
	var count uint64
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		count = tx.Size(payloadDeliveredBlockHashMapPth)
		return nil
	}); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *store) BidTrace(slot uint64, proposerPubKey types.PublicKey, blockHash types.Hash) (*BidTrace, error) {
	var bidTrace BidTrace

	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(bidTraceMapPth.Append(prefixLongKey(slot, proposerPubKey.String(), blockHash.String())))
		if b == nil {
			return nil
		}

		var btTime BidTraceTimestamp
		err := json.Unmarshal(b, &btTime)
		if err != nil {
			return err
		}

		if time.Since(btTime.Timestamp) > expireBidAfter {
			return ErrBidTraceExpired
		}

		bidTrace = btTime.BidTrace
		return nil
	}); err != nil {
		return nil, err
	}

	return &bidTrace, nil
}

func (s *store) PutBidTrace(bidTrace BidTraceTimestamp) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(bidTrace)
		if err != nil {
			return err
		}
		tx.Put(bidTraceMapPth.Append(prefixLongKey(bidTrace.Slot, bidTrace.ProposerPubkey.String(), bidTrace.BlockHash.String())), b)
		logger.Debug("PutBidTrace", "slot", bidTrace.Slot, "proposerPubkey", bidTrace.ProposerPubkey, "blockHash", bidTrace.BlockHash)
		return nil
	})
}

// blockHash is parentHash here
func (s *store) PutExecutedPayload(slot uint64, proposerKey types.PublicKey, blockHash types.Hash, payload VersionedExecutedPayload) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		tx.Put(payloadExecutedMapPth.Append(prefixLongKey(slot, proposerKey.String(), blockHash.String())), b)
		logger.Debug("PutExecutedPayload", "slot", slot, "proposerPubkey", proposerKey, "blockHash", blockHash)
		return nil
	})
}

func (s *store) ExecutedPayload(slot uint64, proposerKey types.PublicKey, blockHash types.Hash) (*GetPayloadResponse, error) {
	var payload GetPayloadResponse
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(payloadExecutedMapPth.Append(prefixLongKey(slot, proposerKey.String(), blockHash.String())))
		var v VersionedExecutedPayload
		err := json.Unmarshal(b, &v)
		if err != nil {
			return err
		}
		payload = GetPayloadResponse{
			Capella: v.Capella,
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (s *store) PutBuilderBlockSubmissionsPayload(payload BidTraceExtended) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		blockHashPth := payloadSubmissionsBlockHashMapPth.Append(payload.BlockHash.String())
		tx.Put(blockHashPth, b)

		blockNumberPth := payloadSubmissionsBlockNumberMapPth.Append(prefixKey(payload.BlockNumber))
		if !tx.Exists(blockNumberPth) {
			tx.CreateMap(blockNumberPth)
		}
		tx.Put(blockNumberPth.Append(payload.BlockHash.String()), []byte{})

		slotPth := payloadSubmissionsSlotMapPth.Append(prefixKey(payload.Slot))
		if !tx.Exists(slotPth) {
			tx.CreateMap(slotPth)
		}
		tx.Put(slotPth.Append(payload.BlockHash.String()), []byte{})

		logger.Debug("PutBuilderBlockSubmissionsPayload", "slot", payload.Slot, "blockHash", payload.BlockHash, "blockNumber", payload.BlockNumber)
		return nil
	})
}

func (s *store) BlockSubmissionsPayload(query BuilderBlockQuery) ([]BidTraceReceived, error) {
	submissions := make([]BidTraceReceived, 0)

	if query.Limit == 0 {
		return submissions, nil
	}

	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		if (query.BlockHash != types.Hash{}) {
			pth := payloadSubmissionsBlockHashMapPth.Append(query.BlockHash.String())
			if !tx.Exists(pth) {
				return nil
			}
			var payload BidTraceExtended
			b := tx.Get(pth)
			if err := json.Unmarshal(b, &payload); err != nil {
				return err
			}
			submissions = append(submissions, BidTraceReceived{
				BidTrace:    payload.BidTrace,
				Timestamp:   payload.Timestamp.Unix(),
				TimestampMs: payload.Timestamp.UnixMilli(),
			})
			return nil
		}

		num := 0
		blockHashes := make([]string, 0)
		if query.Slot != 0 {
			pth := payloadSubmissionsSlotMapPth.Append(prefixKey(query.Slot))
			if !tx.Exists(pth) {
				return nil
			}
			for it := tx.Iterator(pth); !it.IsDone(); it.Next() {
				blockHash := it.GetKey()
				blockHashes = append(blockHashes, blockHash)
			}
			num++
		}

		if query.BlockNumber != 0 {
			pth := payloadSubmissionsBlockNumberMapPth.Append(prefixKey(query.BlockNumber))
			if !tx.Exists(pth) {
				return nil
			}
			for it := tx.Iterator(pth); !it.IsDone(); it.Next() {
				blockHash := it.GetKey()
				blockHashes = append(blockHashes, blockHash)
			}
			num++
		}

		searchBlockHashes := make([]string, 0)
		if num == 0 {
			it := tx.Iterator(payloadSubmissionsSlotMapPth)
			it.Last()
			var i uint64 = 0
			limit := query.Limit
			for ; !it.IsDone(); it.Prev() {
				if i >= limit {
					break
				}

				pth := payloadSubmissionsSlotMapPth.Append(it.GetKey())
				for it := tx.Iterator(pth); !it.IsDone(); it.Next() {
					if i >= limit {
						break
					}
					blockHash := it.GetKey()
					searchBlockHashes = append(searchBlockHashes, blockHash)
					i++
				}
			}
		} else {
			blockHashNum := make(map[string]int)
			for _, blockHash := range blockHashes {
				blockHashNum[blockHash]++
			}

			for blockHash, n := range blockHashNum {
				if n != num {
					continue
				}
				searchBlockHashes = append(searchBlockHashes, blockHash)
			}
		}

		for _, blockHash := range searchBlockHashes {
			if !tx.Exists(payloadSubmissionsBlockHashMapPth.Append(blockHash)) {
				continue
			}
			var payload BidTraceExtended
			b := tx.Get(payloadSubmissionsBlockHashMapPth.Append(blockHash))
			if err := json.Unmarshal(b, &payload); err != nil {
				return err
			}

			submissions = append(submissions, BidTraceReceived{
				BidTrace:    payload.BidTrace,
				Timestamp:   payload.Timestamp.Unix(),
				TimestampMs: payload.Timestamp.UnixMilli(),
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}

	sort.SliceStable(submissions, func(i, j int) bool {
		return submissions[i].Slot > submissions[j].Slot // descending
	})

	limit := uint64(len(submissions))
	if limit > query.Limit {
		limit = query.Limit
	}

	return submissions[0:limit], nil
}

func (s *store) LatestBuilderBid(slot uint64, parentHash types.Hash, proposerKey, builderKey types.PublicKey) (*BuilderBidHeaderResponse, error) {
	var header BuilderBidHeaderResponse
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(headerBidBuilderMapPth.Append(
			prefixLongKey(slot, parentHash.String(), proposerKey.String()),
			builderKey.String(),
		))
		if err := json.Unmarshal(b, &header); err != nil {
			return err
		}

		if time.Since(header.Timestamp) > expireBidAfter {
			return ErrLatestBuilderBidExpired
		}

		return nil
	}); err != nil {
		return nil, err
	}
	return &header, nil
}

// save the latest bid by a specific builder
func (s *store) PutLatestBuilderBid(slot uint64, parentHash types.Hash, proposerKey, builderKey types.PublicKey, payload BuilderBidHeaderResponse) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		blockKey := prefixLongKey(slot, parentHash.String(), proposerKey.String())
		pth := headerBidBuilderMapPth.Append(blockKey)
		if !tx.Exists(pth) {
			tx.CreateMap(pth)
		}

		// payload/response
		tx.Put(pth.Append(builderKey.String()), b)
		logger.Debug("PutLatestBuilderBid", "slot", slot, "proposerPubkey", proposerKey, "builderPubkey", builderKey, "parentHash", parentHash)
		return nil
	})
}

func (s *store) BestBid(slot uint64, parentHash types.Hash, proposerKey types.PublicKey) (*GetHeaderResponse, error) {
	var payload GetHeaderResponse
	if err := bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		pth := headerBestBidMapPth.Append(prefixLongKey(slot, parentHash.String(), proposerKey.String()))
		if !tx.Exists(pth) {
			return ErrBestBidNotFound
		}

		b := tx.Get(pth)
		var topBuilderBid BuilderBidHeaderResponse
		err := json.Unmarshal(b, &topBuilderBid)

		if err != nil {
			return err
		}

		if time.Since(topBuilderBid.Timestamp) > expireBidAfter {
			return ErrBestBidExpired
		}

		payload = GetHeaderResponse{
			Capella: topBuilderBid.Capella,
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (s *store) UpdateBestBid(slot uint64, parentHash types.Hash, proposerKey types.PublicKey) error {
	return bolted.SugaredWrite(s.db, func(tx bolted.SugaredWriteTx) error {
		maxBid := big.NewInt(0)
		var topBuilderBid *BuilderBidHeaderResponse
		for it := tx.Iterator(headerBidBuilderMapPth.Append(prefixLongKey(slot, parentHash.String(), proposerKey.String()))); !it.IsDone(); it.Next() {
			var builder BuilderBidHeaderResponse
			if err := json.Unmarshal(it.GetValue(), &builder); err != nil {
				return err
			}

			// filter out builders that have an older bid
			if time.Since(builder.Timestamp) > expireBidAfter {
				continue
			}

			// get the highest amount bid builder
			if builder.Value().Cmp(maxBid) > 0 {
				maxBid = builder.Value()
				topBuilderBid = &builder
			}
		}

		if topBuilderBid == nil {
			return ErrUpdateBestBid
		}

		tb, err := json.Marshal(topBuilderBid)
		if err != nil {
			return err
		}

		tx.Put(headerBestBidMapPth.Append(prefixLongKey(slot, parentHash.String(), proposerKey.String())), tb)
		logger.Debug("UpdateBestBid", "slot", slot, "proposerPubkey", proposerKey, "parentHash", parentHash)
		return nil
	})
}

func createStore(pth string, mapPths []dbpath.Path) (bolted.Database, error) {
	db, err := connectStore(pth)
	if err != nil {
		return nil, err
	}

	if err := bolted.SugaredWrite(db, func(tx bolted.SugaredWriteTx) error {
		for _, pth := range mapPths {
			if !tx.Exists(pth) {
				tx.CreateMap(pth)
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return db, nil
}

func connectStore(filepath string) (bolted.Database, error) {
	db, err := embedded.Open(
		filepath,
		0700,
		embedded.Options{
			Options: bbolt.Options{
				Timeout:      1 * time.Second,
				FreelistType: bbolt.FreelistMapType,
				PageSize:     8192,
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return db, nil
}

func intToByteArray[T uint64 | int64](i T) []byte {
	var b []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh.Len = 8
	sh.Cap = 8
	sh.Data = uintptr(unsafe.Pointer(&i))

	return b[:]
}

func byteArrayToInt[T uint64 | int64](b []byte) T {
	return *(*T)(unsafe.Pointer(&b[0]))
}

func joinPubKeys(elems []types.PublicKey, sep string) string {
	str := make([]string, len(elems))
	for i, elem := range elems {
		str[i] = elem.String()
	}
	return strings.Join(str, sep)
}

func joinDBPth(prefix, suffix string) string {
	return fmt.Sprintf("%s.%s", prefix, suffix)
}

func prefixKey(n uint64) string {
	return fmt.Sprintf("%018d", n)
}

func prefixLongKey(n uint64, str, str2 string) string {
	return fmt.Sprintf("%018d_%s_%s", n, str, str2)
}

func prefixWithZeroAndLimit(n *big.Int, length int) string {
	s := n.String()
	if len(s) > length {
		s = s[:length]
	} else {
		s = fmt.Sprintf("%0*d", length, n)
	}
	return s
}
