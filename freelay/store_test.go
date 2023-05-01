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
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	builderapi "github.com/attestantio/go-builder-client/api"
	buildercapella "github.com/attestantio/go-builder-client/api/capella"
	builderspec "github.com/attestantio/go-builder-client/spec"
	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/draganm/bolted"
	"github.com/draganm/bolted/dbpath"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"
)

func TestPrefixWithZeroAndLimit(t *testing.T) {
	n := big.NewInt(1234567)
	p := prefixWithZeroAndLimit(n, 3)
	require.Equal(t, "123", p)

	n = big.NewInt(12)
	p = prefixWithZeroAndLimit(n, 8)
	require.Equal(t, "00000012", p)
}

func TestActiveValidatorStats(t *testing.T) {
	var (
		store, pths = newTestStore(t)
		pubKeys     = []types.PublicKey{types.PublicKey(random48Bytes()), types.PublicKey(random48Bytes()), types.PublicKey(random48Bytes())}
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	pbKeys, err := store.ActiveValidatorsStats()
	require.NoError(t, err)
	require.Zero(t, len(pbKeys))

	err = store.SetActiveValidatorsStats(pubKeys)
	require.NoError(t, err)

	pbKeys, err = store.ActiveValidatorsStats()
	require.NoError(t, err)
	require.Len(t, pbKeys, 3)

	err = store.SetActiveValidatorsStats([]types.PublicKey{pubKeys[0], pubKeys[2]})
	require.NoError(t, err)

	pbKeys, err = store.ActiveValidatorsStats()
	require.NoError(t, err)
	require.Len(t, pbKeys, 2)
}

func TestBlockBuilder(t *testing.T) {
	var (
		store, pths    = newTestStore(t)
		pubKey         = types.PublicKey(random48Bytes())
		pubKey2        = types.PublicKey(random48Bytes())
		pubKey3        = types.PublicKey(random48Bytes())
		highPriorities = []bool{true, false}
		blacklisteds   = []bool{false, false}
		now            = time.Now().UTC()
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	b, err := store.BlockBuilder(pubKey)
	require.Error(t, err)
	require.Nil(t, b)

	err = store.SetBlockBuilderStatus(pubKey, highPriorities[0], blacklisteds[0])
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey)
	require.NoError(t, err)
	require.Equal(t, highPriorities[0], b.HighPriority)
	require.Equal(t, blacklisteds[0], b.Blacklisted)

	err = store.SetBlockBuilderStatus(pubKey, highPriorities[1], blacklisteds[1])
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey)
	require.NoError(t, err)
	require.Equal(t, highPriorities[1], b.HighPriority)
	require.Equal(t, blacklisteds[1], b.Blacklisted)
	require.NoError(t, err)

	var pubKeys []types.PublicKey
	err = bolted.SugaredRead(store.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(blockBuilderMapPth); !it.IsDone(); it.Next() {
			pb, err := types.HexToPubkey(it.GetKey())
			require.NoError(t, err)
			pubKeys = append(pubKeys, pb)
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []types.PublicKey{pubKey}, pubKeys)

	prevB := b
	err = store.UpsertBlockBuilderSubmissionPayload(pubKey, 1, "0x1234/1_0x5678", nil)
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey)
	require.NoError(t, err)
	require.Greater(t, b.LastSubmissionSlot, prevB.LastSubmissionSlot)
	require.Equal(t, uint64(1), b.LastSubmissionSlot)
	require.Greater(t, b.NumSubmissionsTotal, prevB.NumSubmissionsTotal)
	require.Equal(t, uint64(1), b.NumSubmissionsTotal)
	require.Equal(t, "0x1234/1_0x5678", b.LastSubmissionID)
	require.Equal(t, uint64(1), b.NumSubmissionsTotal)
	require.Equal(t, uint64(0), b.NumSubmissionsSimFailed)
	require.Greater(t, b.UpdatedAt, prevB.UpdatedAt)
	require.Equal(t, prevB.CreatedAt, b.CreatedAt)

	err = store.UpsertBlockBuilderSubmissionPayload(pubKey, 8, "0x1234/1_0x5679", nil)
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey)
	require.NoError(t, err)
	require.Equal(t, uint64(8), b.LastSubmissionSlot)
	require.Equal(t, uint64(2), b.NumSubmissionsTotal)
	require.Equal(t, "0x1234/1_0x5679", b.LastSubmissionID)
	require.Greater(t, b.UpdatedAt, prevB.UpdatedAt)
	require.Equal(t, prevB.CreatedAt, b.CreatedAt)

	simErr := fmt.Errorf("sim error")
	err = store.UpsertBlockBuilderSubmissionPayload(pubKey2, 2, "0x1234/1_0x5678", simErr)
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey2)
	require.NoError(t, err)
	require.Equal(t, uint64(2), b.LastSubmissionSlot)
	require.Equal(t, uint64(1), b.NumSubmissionsTotal)
	require.Equal(t, "0x1234/1_0x5678", b.LastSubmissionID)
	require.Equal(t, uint64(1), b.NumSubmissionsSimFailed)
	require.True(t, b.CreatedAt.After(now))
	require.True(t, b.UpdatedAt.After(now))

	prevB = b
	err = store.UpsertBlockBuilderDeliveredPayload(pubKey2, 3, "0x1234/1_0x5678")
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey2)
	require.NoError(t, err)
	require.Equal(t, uint64(3), b.LastDeliveredSlot)
	require.Equal(t, uint64(1), b.NumDeliveredTotal)
	require.Equal(t, "0x1234/1_0x5678", b.LastDeliveredID)
	require.True(t, b.UpdatedAt.After(prevB.UpdatedAt))
	require.Equal(t, prevB.CreatedAt, b.CreatedAt)

	err = store.UpsertBlockBuilderDeliveredPayload(pubKey2, 9, "0x1234/1_0x5679")
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey2)
	require.NoError(t, err)
	require.Equal(t, uint64(9), b.LastDeliveredSlot)
	require.Equal(t, uint64(2), b.NumDeliveredTotal)
	require.Equal(t, "0x1234/1_0x5679", b.LastDeliveredID)
	require.True(t, b.UpdatedAt.After(prevB.UpdatedAt))
	require.Equal(t, prevB.CreatedAt, b.CreatedAt)

	err = store.UpsertBlockBuilderDeliveredPayload(pubKey3, 4, "0x1234/1_0x5678")
	require.NoError(t, err)
	b, err = store.BlockBuilder(pubKey3)
	require.NoError(t, err)
	require.Equal(t, uint64(4), b.LastDeliveredSlot)
	require.Equal(t, uint64(1), b.NumDeliveredTotal)
	require.Equal(t, "0x1234/1_0x5678", b.LastDeliveredID)
	require.True(t, b.CreatedAt.After(now))
	require.True(t, b.UpdatedAt.After(now))

	known, err := store.IsKnownBlockBuilder(pubKey)
	require.NoError(t, err)
	require.True(t, known)

	known, err = store.IsKnownBlockBuilder(types.PublicKey(random48Bytes()))
	require.NoError(t, err)
	require.False(t, known)

	allowed, err := store.AreNewBlockBuildersAccepted()
	require.Error(t, err)
	require.True(t, allowed)

	err = store.RejectNewBlockBuilders()
	require.NoError(t, err)
	allowed, err = store.AreNewBlockBuildersAccepted()
	require.NoError(t, err)
	require.False(t, allowed)

	err = store.AcceptNewBlockBuilders()
	require.NoError(t, err)
	allowed, err = store.AreNewBlockBuildersAccepted()
	require.NoError(t, err)
	require.True(t, allowed)
}

func TestLatestSlotStats(t *testing.T) {
	var (
		store, pths = newTestStore(t)
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	_, err := store.LatestSlotStats()
	require.Error(t, err)

	err = store.SetLatestSlotStats(1)
	require.NoError(t, err)
	s, err := store.LatestSlotStats()
	require.NoError(t, err)
	require.Equal(t, uint64(1), s)

	err = store.SetLatestSlotStats(2)
	require.NoError(t, err)
	s, err = store.LatestSlotStats()
	require.NoError(t, err)
	require.Equal(t, uint64(2), s)
}

func TestLatestDeliveredSlotStats(t *testing.T) {
	var (
		store, pths = newTestStore(t)
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	_, err := store.LatestDeliveredSlotStats()
	require.Error(t, err)

	err = store.SetLatestDeliveredSlotStats(1)
	require.NoError(t, err)
	s, err := store.LatestDeliveredSlotStats()
	require.NoError(t, err)
	require.Equal(t, uint64(1), s)

	err = store.SetLatestDeliveredSlotStats(2)
	require.NoError(t, err)
	s, err = store.LatestDeliveredSlotStats()
	require.NoError(t, err)
	require.Equal(t, uint64(2), s)
}

func TestValidators(t *testing.T) {
	var (
		store, pths = newTestStore(t)
		validators  = []SignedValidatorRegistrationExtended{
			{
				SignedValidatorRegistration: types.SignedValidatorRegistration{
					Message: &types.RegisterValidatorRequestMessage{
						FeeRecipient: types.Address(random20Bytes()),
						Timestamp:    1234356,
						GasLimit:     278234191203,
						Pubkey:       types.PublicKey(random48Bytes()),
					},
					Signature: types.Signature(random96Bytes()),
				},
				Timestamp: time.Now().UTC(),
				IP:        "192.168.0.1",
			},
			{
				SignedValidatorRegistration: types.SignedValidatorRegistration{
					Message: &types.RegisterValidatorRequestMessage{
						FeeRecipient: types.Address(random20Bytes()),
						Timestamp:    654321,
						GasLimit:     321234532,
						Pubkey:       types.PublicKey(random48Bytes()),
					},
					Signature: types.Signature(random96Bytes()),
				},
				Timestamp: time.Now().UTC(),
				IP:        "192.160.0.2",
			},
		}
		pubKey = types.PublicKey(random48Bytes())
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	_, err := store.RegisteredValidator(validators[0].Message.Pubkey)
	require.Error(t, err)

	err = store.PutRegistrationValidator(validators[0].Message.Pubkey, validators[0])
	require.NoError(t, err)
	v, err := store.RegisteredValidator(validators[0].Message.Pubkey)
	require.NoError(t, err)
	require.Equal(t, &validators[0].SignedValidatorRegistration, v)

	err = store.PutRegistrationValidator(validators[1].Message.Pubkey, validators[1])
	require.NoError(t, err)

	err = bolted.SugaredWrite(store.db, func(tx bolted.SugaredWriteTx) error {
		b, err := json.Marshal(validators[0].SignedValidatorRegistration)
		if err != nil {
			return err
		}
		tx.Put(validatorMapPth.Append(pubKey.String()), b)
		return nil
	})
	require.NoError(t, err)

	vs, err := store.AllRegisteredValidators()
	require.NoError(t, err)
	require.Equal(t, 3, len(vs))
	require.Contains(t, vs, validators[0].SignedValidatorRegistration)
	require.Contains(t, vs, validators[1].SignedValidatorRegistration)
}

func TestDeliveredPayload(t *testing.T) {
	var (
		store, pths = newTestStore(t)
		proposerKey = types.PublicKey(random48Bytes())
		blockNum    = 3
		blockHash   = types.Hash(random32Bytes())
		bdt         = time.Now().UTC()
		payloads    = []BidTraceReceived{
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:                 1,
						ParentHash:           types.Hash(random32Bytes()),
						BlockHash:            types.Hash(random32Bytes()),
						BuilderPubkey:        types.PublicKey(random48Bytes()),
						ProposerPubkey:       proposerKey,
						ProposerFeeRecipient: types.Address(random20Bytes()),
						Value:                types.IntToU256(1),
						GasLimit:             5002,
						GasUsed:              5003,
					},
					NumTx:       1,
					BlockNumber: uint64(blockNum),
				},
				Timestamp:   bdt.Unix(),
				TimestampMs: bdt.UnixMilli(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:                 2,
						ParentHash:           types.Hash(random32Bytes()),
						BlockHash:            blockHash,
						BuilderPubkey:        types.PublicKey(random48Bytes()),
						ProposerPubkey:       proposerKey,
						ProposerFeeRecipient: types.Address(random20Bytes()),
						Value:                types.IntToU256(3),
						GasLimit:             5002,
						GasUsed:              5003,
					},
					NumTx:       2,
					BlockNumber: 2,
				},
				Timestamp:   bdt.Unix(),
				TimestampMs: bdt.UnixMilli(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:                 2,
						ParentHash:           types.Hash(random32Bytes()),
						BlockHash:            types.Hash(random32Bytes()),
						BuilderPubkey:        types.PublicKey(random48Bytes()),
						ProposerPubkey:       types.PublicKey(random48Bytes()),
						ProposerFeeRecipient: types.Address(random20Bytes()),
						Value:                types.IntToU256(4),
						GasLimit:             5002,
						GasUsed:              5003,
					},
					NumTx:       3,
					BlockNumber: uint64(blockNum),
				},
				Timestamp:   bdt.Unix(),
				TimestampMs: bdt.UnixMilli(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:                 3,
						ParentHash:           types.Hash(random32Bytes()),
						BlockHash:            types.Hash(random32Bytes()),
						BuilderPubkey:        types.PublicKey(random48Bytes()),
						ProposerPubkey:       types.PublicKey(random48Bytes()),
						ProposerFeeRecipient: types.Address(random20Bytes()),
						Value:                types.IntToU256(2),
						GasLimit:             5002,
						GasUsed:              5003,
					},
					NumTx:       4,
					BlockNumber: uint64(blockNum),
				},
				Timestamp:   bdt.Unix(),
				TimestampMs: bdt.UnixMilli(),
			},
		}
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	p, err := store.DeliveredPayloads(ProposerPayloadQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))

	for indx, payload := range payloads {
		if indx < 2 {
			eth1BlockHash32 := random32Bytes()
			eth1BlockHash := eth1BlockHash32[:]
			syncCommitte64 := random64Bytes()
			syncCommitte := syncCommitte64[:]
			err = store.PutDeliveredPayload(DeliveredPayload{
				BidTrace: payload.BidTrace,
				SignedBlindedBeaconBlock: &SignedBlindedBeaconBlock{
					Capella: &apicapella.SignedBlindedBeaconBlock{
						Message: &apicapella.BlindedBeaconBlock{
							Slot:          1,
							ProposerIndex: 1,
							ParentRoot:    phase0.Root(random32Bytes()),
							StateRoot:     phase0.Root(random32Bytes()),
							Body: &apicapella.BlindedBeaconBlockBody{
								RANDAOReveal: phase0.BLSSignature(random96Bytes()),
								ETH1Data: &phase0.ETH1Data{
									BlockHash: eth1BlockHash,
								},
								Graffiti:          random32Bytes(),
								ProposerSlashings: []*phase0.ProposerSlashing{},
								AttesterSlashings: []*phase0.AttesterSlashing{},
								Attestations:      []*phase0.Attestation{},
								Deposits:          []*phase0.Deposit{},
								VoluntaryExits:    []*phase0.SignedVoluntaryExit{},
								SyncAggregate: &altair.SyncAggregate{
									SyncCommitteeBits: bitfield.Bitvector512(syncCommitte),
								},
								ExecutionPayloadHeader: &consensuscapella.ExecutionPayloadHeader{
									ParentHash:       phase0.Hash32(random32Bytes()),
									BlockHash:        phase0.Hash32(random32Bytes()),
									ExtraData:        []byte{0x01, 0x02, 0x03},
									TransactionsRoot: phase0.Root{},
									WithdrawalsRoot:  phase0.Root{},
								},
								BLSToExecutionChanges: []*consensuscapella.SignedBLSToExecutionChange{},
							},
						},
						Signature: phase0.BLSSignature(random96Bytes()),
					},
				},
				Timestamp: time.UnixMilli(payload.TimestampMs),
			})
			require.NoError(t, err)
		} else {
			err = store.PutDeliveredPayload(DeliveredPayload{
				BidTrace: payload.BidTrace,
				SignedBlindedBeaconBlock: &SignedBlindedBeaconBlock{
					Bellatrix: &types.SignedBlindedBeaconBlock{
						Message: &types.BlindedBeaconBlock{
							Body: &types.BlindedBeaconBlockBody{
								Eth1Data:          &types.Eth1Data{},
								ProposerSlashings: []*types.ProposerSlashing{},
								AttesterSlashings: []*types.AttesterSlashing{},
								Attestations:      []*types.Attestation{},
								Deposits:          []*types.Deposit{},
								VoluntaryExits:    []*types.SignedVoluntaryExit{},
								SyncAggregate:     &types.SyncAggregate{},
								ExecutionPayloadHeader: &types.ExecutionPayloadHeader{
									BlockHash:  types.Hash(random32Bytes()),
									ParentHash: types.Hash(random32Bytes()),
								},
							},
						},
					},
				},
				Timestamp: time.UnixMilli(payload.TimestampMs),
			})
			require.NoError(t, err)
		}
	}

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Slot: 1})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[0], p[0])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Slot: 2, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 2, len(p))
	require.Contains(t, p, payloads[1])
	require.Contains(t, p, payloads[2])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Slot: 2, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Cursor: 2, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 3, len(p))
	require.Equal(t, payloads[0], p[2])
	require.Contains(t, p, payloads[0])
	require.Contains(t, p, payloads[1])
	require.Contains(t, p, payloads[2])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{ProposerPubkey: proposerKey, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 2, len(p))
	require.Equal(t, payloads[1], p[0])
	require.Equal(t, payloads[0], p[1])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{BlockNumber: uint64(blockNum), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 3, len(p))
	require.Equal(t, payloads[3], p[0])
	require.Equal(t, payloads[2], p[1])
	require.Equal(t, payloads[0], p[2])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{BlockHash: blockHash, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[1], p[0])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{BlockHash: blockHash, BlockNumber: uint64(blockNum), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[1], p[0])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Slot: 2, ProposerPubkey: proposerKey, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[1], p[0])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Slot: 1, BlockNumber: uint64(blockNum), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[0], p[0])

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Limit: 10, OrderBy: -1})
	require.NoError(t, err)
	require.Equal(t, 4, len(p))
	require.Equal(t, []BidTraceReceived{payloads[2], payloads[1], payloads[3], payloads[0]}, p)

	p, err = store.DeliveredPayloads(ProposerPayloadQuery{Limit: 10, OrderBy: 1})
	require.NoError(t, err)
	require.Equal(t, 4, len(p))
	require.Equal(t, []BidTraceReceived{payloads[0], payloads[3], payloads[1], payloads[2]}, p)

	count, err := store.DeliveredPayloadsCount()
	require.NoError(t, err)
	require.Equal(t, uint64(4), count)
}

func TestExecutedPayload(t *testing.T) {
	var (
		store, pths = newTestStore(t)
		slot        = uint64(1)
		proposerKey = types.PublicKey(random48Bytes())
		blockHash   = types.Hash(random32Bytes())
		payload     = VersionedExecutedPayload{
			Capella: &builderapi.VersionedExecutionPayload{
				Version: consensusspec.DataVersionCapella,
				Capella: &consensuscapella.ExecutionPayload{
					ParentHash:   phase0.Hash32(random32Bytes()),
					FeeRecipient: consensusbellatrix.ExecutionAddress(random20Bytes()),
					StateRoot:    random32Bytes(),
					ReceiptsRoot: random32Bytes(),
					LogsBloom:    random256Bytes(),
					PrevRandao:   random32Bytes(),
					BlockNumber:  1000,
					GasLimit:     50,
					GasUsed:      10,
					Timestamp:    100,
					ExtraData:    []byte{0x1, 0x2, 0x3, 0x4, 0x5},
					BlockHash:    phase0.Hash32(random32Bytes()),
					Transactions: []consensusbellatrix.Transaction{},
					Withdrawals:  []*consensuscapella.Withdrawal{},
				},
			},
			Timestamp: time.Now().UTC(),
		}
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	_, err := store.ExecutedPayload(1, types.PublicKey(random48Bytes()), types.Hash(random32Bytes()))
	require.Error(t, err)

	err = store.PutExecutedPayload(slot, proposerKey, blockHash, payload)
	require.NoError(t, err)
	e, err := store.ExecutedPayload(slot, proposerKey, blockHash)
	require.NoError(t, err)
	require.Equal(t, &GetPayloadResponse{
		Capella: payload.Capella,
	}, e)
}

func TestSubmissionPayload(t *testing.T) {
	var (
		store, pths = newTestStore(t)
		payloads    = []BidTraceExtended{
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:      1,
						BlockHash: types.Hash(random32Bytes()),
					},
					BlockNumber: 1,
				},
				Timestamp: time.Now().UTC(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:      1,
						BlockHash: types.Hash(random32Bytes()),
					},
					BlockNumber: 2,
				},
				Timestamp: time.Now().UTC(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:      2,
						BlockHash: types.Hash(random32Bytes()),
					},
					BlockNumber: 1,
				},
				Timestamp: time.Now().UTC(),
			},
		}
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	p, err := store.BlockSubmissionsPayload(BuilderBlockQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))

	err = store.PutBuilderBlockSubmissionsPayload(payloads[0])
	require.NoError(t, err)
	p, err = store.BlockSubmissionsPayload(BuilderBlockQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, BidTraceReceived{
		BidTrace:    payloads[0].BidTrace,
		Timestamp:   payloads[0].Timestamp.Unix(),
		TimestampMs: payloads[0].Timestamp.UnixMilli(),
	}, p[0])

	for _, p := range payloads[1:] {
		err = store.PutBuilderBlockSubmissionsPayload(p)
		require.NoError(t, err)
	}

	p, err = store.BlockSubmissionsPayload(BuilderBlockQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 2, len(p))
	require.Contains(t, p, BidTraceReceived{
		BidTrace:    payloads[0].BidTrace,
		Timestamp:   payloads[0].Timestamp.Unix(),
		TimestampMs: payloads[0].Timestamp.UnixMilli(),
	})
	require.Contains(t, p, BidTraceReceived{
		BidTrace:    payloads[1].BidTrace,
		Timestamp:   payloads[1].Timestamp.Unix(),
		TimestampMs: payloads[1].Timestamp.UnixMilli(),
	})

	p, err = store.BlockSubmissionsPayload(BuilderBlockQuery{Slot: 1, BlockNumber: uint64(payloads[1].BlockNumber), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, p[0], BidTraceReceived{
		BidTrace:    payloads[1].BidTrace,
		Timestamp:   payloads[1].Timestamp.Unix(),
		TimestampMs: payloads[1].Timestamp.UnixMilli(),
	})

	p, err = store.BlockSubmissionsPayload(BuilderBlockQuery{Slot: 2, Limit: 0})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))
}

func TestBidTrace(t *testing.T) {
	var (
		store, pths = newTestStore(t)
		payloads    = []BidTrace{
			{
				BidTrace: types.BidTrace{
					Slot:           1,
					BlockHash:      types.Hash(random32Bytes()),
					ProposerPubkey: types.PublicKey(random48Bytes()),
				},
				BlockNumber: 1,
			},
		}
	)
	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	bt, err := store.BidTrace(uint64(1), types.PublicKey(random48Bytes()), types.Hash(random32Bytes()))
	require.Error(t, err)
	require.Nil(t, bt)

	for _, p := range payloads {
		err = store.PutBidTrace(BidTraceTimestamp{
			BidTrace:  p,
			Timestamp: time.Now().UTC(),
		})
		require.NoError(t, err)
	}

	bt, err = store.BidTrace(uint64(1), types.PublicKey(random48Bytes()), types.Hash(random32Bytes()))
	require.Error(t, err)
	require.Nil(t, bt)

	bt, err = store.BidTrace(uint64(1), payloads[0].ProposerPubkey, payloads[0].BlockHash)
	require.NoError(t, err)
	require.Equal(t, payloads[0], *bt)

	err = store.PutBidTrace(BidTraceTimestamp{
		BidTrace:  payloads[0],
		Timestamp: time.Now().UTC().Add(-time.Hour),
	})
	require.NoError(t, err)

	bt, err = store.BidTrace(uint64(1), payloads[0].ProposerPubkey, payloads[0].BlockHash)
	require.Error(t, err)
	require.Nil(t, bt)
	require.Equal(t, ErrBidTraceExpired, err)
}

func TestLatestBuilderBidAndBestBid(t *testing.T) {
	var (
		store, pths = newTestStore(t)
		parentHash  = []types.Hash{types.Hash(random32Bytes()), types.Hash(random32Bytes())}
		proposerKey = []types.PublicKey{types.PublicKey(random48Bytes()), types.PublicKey(random48Bytes())}
		builderKey  = []types.PublicKey{types.PublicKey(random48Bytes()), types.PublicKey(random48Bytes())}
		slot        = uint64(1)
		payloads    = []BuilderBidHeaderResponse{
			{
				Capella: &builderspec.VersionedSignedBuilderBid{
					Version: consensusspec.DataVersionCapella,
					Capella: &buildercapella.SignedBuilderBid{
						Message: &buildercapella.BuilderBid{
							Value:  uint256.NewInt(101),
							Pubkey: phase0.BLSPubKey(random48Bytes()),
							Header: &consensuscapella.ExecutionPayloadHeader{
								ParentHash:       phase0.Hash32(parentHash[0]),
								FeeRecipient:     consensusbellatrix.ExecutionAddress(random20Bytes()),
								StateRoot:        random32Bytes(),
								ReceiptsRoot:     random32Bytes(),
								LogsBloom:        random256Bytes(),
								PrevRandao:       random32Bytes(),
								BlockNumber:      1000,
								GasLimit:         50,
								GasUsed:          10,
								Timestamp:        100,
								ExtraData:        []byte{0x1, 0x2, 0x3, 0x4, 0x5},
								BaseFeePerGas:    random32Bytes(),
								BlockHash:        phase0.Hash32(random32Bytes()),
								TransactionsRoot: phase0.Root(random32Bytes()),
								WithdrawalsRoot:  phase0.Root(random32Bytes()),
							},
						},
						Signature: phase0.BLSSignature(random96Bytes()),
					},
				},
				Timestamp: time.Now().UTC(),
			},
			{
				Capella: &builderspec.VersionedSignedBuilderBid{
					Version: consensusspec.DataVersionCapella,
					Capella: &buildercapella.SignedBuilderBid{
						Message: &buildercapella.BuilderBid{
							Value:  uint256.NewInt(102),
							Pubkey: phase0.BLSPubKey(random48Bytes()),
							Header: &consensuscapella.ExecutionPayloadHeader{
								ParentHash:       phase0.Hash32(parentHash[0]),
								FeeRecipient:     consensusbellatrix.ExecutionAddress(random20Bytes()),
								StateRoot:        random32Bytes(),
								ReceiptsRoot:     random32Bytes(),
								LogsBloom:        random256Bytes(),
								PrevRandao:       random32Bytes(),
								BlockNumber:      1000,
								GasLimit:         50,
								GasUsed:          10,
								Timestamp:        100,
								ExtraData:        []byte{0x01, 0x02, 0x03, 0x04, 0x05},
								BaseFeePerGas:    random32Bytes(),
								BlockHash:        phase0.Hash32(random32Bytes()),
								TransactionsRoot: phase0.Root(random32Bytes()),
								WithdrawalsRoot:  phase0.Root(random32Bytes()),
							},
						},
						Signature: phase0.BLSSignature(random96Bytes()),
					},
				},
				Timestamp: time.Now().UTC(),
			},
		}
	)

	t.Cleanup(func() {
		testStoreCleanup(t, store, pths)
	})

	_, err := store.LatestBuilderBid(1, types.Hash(random32Bytes()), types.PublicKey(random48Bytes()), types.PublicKey(random48Bytes()))
	require.Error(t, err)

	err = store.PutLatestBuilderBid(slot, parentHash[0], proposerKey[0], builderKey[0], payloads[0])
	require.NoError(t, err)
	e, err := store.LatestBuilderBid(slot, parentHash[0], proposerKey[0], builderKey[0])
	require.NoError(t, err)
	require.Equal(t, &payloads[0], e)

	err = store.PutLatestBuilderBid(slot, parentHash[0], proposerKey[0], builderKey[1], payloads[1])
	require.NoError(t, err)
	e, err = store.LatestBuilderBid(slot, parentHash[0], proposerKey[0], builderKey[1])
	require.NoError(t, err)
	require.Equal(t, &payloads[1], e)

	var p []BuilderBidHeaderResponse
	err = bolted.SugaredRead(store.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(headerBidBuilderMapPth.Append(prefixLongKey(slot, parentHash[0].String(), proposerKey[0].String()))); !it.IsDone(); it.Next() {
			b := it.GetValue()
			var e BuilderBidHeaderResponse
			if err := json.Unmarshal(b, &e); err != nil {
				return err
			}
			p = append(p, e)
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 2, len(p))
	require.Contains(t, p, payloads[0])
	require.Contains(t, p, payloads[1])

	_, err = store.BestBid(1, types.Hash(random32Bytes()), types.PublicKey(random48Bytes()))
	require.Error(t, err)

	err = store.UpdateBestBid(slot, parentHash[0], proposerKey[0])
	require.NoError(t, err)
	bb, err := store.BestBid(slot, parentHash[0], proposerKey[0])
	require.NoError(t, err)
	require.Equal(t, &GetHeaderResponse{Capella: payloads[1].Capella}, bb)

	oldPayload := payloads[0]
	oldPayload.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	err = store.PutLatestBuilderBid(slot, parentHash[1], proposerKey[1], builderKey[1], oldPayload)
	require.NoError(t, err)
	err = store.UpdateBestBid(slot, parentHash[1], proposerKey[1])
	require.Error(t, err)
	require.Equal(t, ErrUpdateBestBid, err)
}

func TestTimestamps(t *testing.T) {
	var (
		pth        = fmt.Sprintf("%d.db", rand.Int())
		dbPth      = dbpath.ToPath("timestamps")
		store, err = createStore(pth, []dbpath.Path{dbPth})
		now        = time.Now().UTC()
		st         = struct{ T time.Time }{T: now}
		b, _       = json.Marshal(st)
		nowMS      = now.UnixMilli()
	)

	require.NoError(t, err)
	t.Cleanup(func() {
		err := store.Close()
		require.NoError(t, err)
		err = os.Remove(pth)
		require.NoError(t, err)
	})

	err = bolted.SugaredWrite(store, func(tx bolted.SugaredWriteTx) error {
		tx.Put(dbPth.Append("time"), b)
		return nil
	})
	require.NoError(t, err)

	var nowRes struct{ T time.Time }
	err = bolted.SugaredRead(store, func(tx bolted.SugaredReadTx) error {
		b := tx.Get(dbPth.Append("time"))
		return json.Unmarshal(b, &nowRes)
	})
	require.NoError(t, err)
	require.Equal(t, now, nowRes.T)
	require.Equal(t, nowMS, nowRes.T.UnixMilli())
}

func newTestStore(t *testing.T) (*store, string) {
	prefix := newTestPrefix()

	store, err := NewStore(prefix)
	require.NoError(t, err)
	return store, prefix
}

func newTestPrefix() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int())
}

func testStoreCleanup(t *testing.T, store *store, prefix string) {
	store.Close()
	testStoreDelete(t, prefix)
}

func testStoreDelete(t *testing.T, prefix string) {
	err := filepath.Walk("./", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if len(info.Name()) < len(prefix) {
			return nil
		}
		if info.Name()[:len(prefix)] == prefix {
			if err := os.Remove(path); err != nil {
				fmt.Println(err)
			}
		}
		return nil
	})
	require.NoError(t, err)
}

func random20Bytes() (b [20]byte) {
	rand.Read(b[:])
	return b
}

func random48Bytes() (b [48]byte) {
	rand.Read(b[:])
	return b
}

func random96Bytes() (b [96]byte) {
	rand.Read(b[:])
	return b
}

func random32Bytes() (b [32]byte) {
	rand.Read(b[:])
	return b
}

func random64Bytes() (b [64]byte) {
	rand.Read(b[:])
	return b
}

func random256Bytes() (b [256]byte) {
	rand.Read(b[:])
	return b
}

func random512Bytes() (b [512]byte) { // nolint: unused
	rand.Read(b[:])
	return b
}
