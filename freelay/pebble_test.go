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
	"fmt"
	"os"
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
	"github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"
)

func TestPebbleDBBlockBuilder(t *testing.T) {
	var (
		store, pths    = newTestPebbleDB(t)
		pubKey         = types.PublicKey(random48Bytes())
		pubKey2        = types.PublicKey(random48Bytes())
		pubKey3        = types.PublicKey(random48Bytes())
		highPriorities = []bool{true, false}
		blacklisteds   = []bool{false, false}
		now            = time.Now().UTC()
	)

	t.Cleanup(func() {
		store.Close()
		cleanupTestPebbleDB(t, pths)
	})

	b, err := store.Builder(pubKey)
	require.Error(t, err)
	require.Nil(t, b)

	err = store.SetBuilderStatus(pubKey, highPriorities[0], blacklisteds[0])
	require.NoError(t, err)
	b, err = store.Builder(pubKey)
	require.NoError(t, err)
	require.Equal(t, highPriorities[0], b.HighPriority)
	require.Equal(t, blacklisteds[0], b.Blacklisted)

	err = store.SetBuilderStatus(pubKey, highPriorities[1], blacklisteds[1])
	require.NoError(t, err)
	b, err = store.Builder(pubKey)
	require.NoError(t, err)
	require.Equal(t, highPriorities[1], b.HighPriority)
	require.Equal(t, blacklisteds[1], b.Blacklisted)
	require.NoError(t, err)

	prevB := b
	err = store.UpsertBuilderSubmitted(pubKey, 1, "0x1234/1_0x5678", nil)
	require.NoError(t, err)
	b, err = store.Builder(pubKey)
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

	err = store.UpsertBuilderSubmitted(pubKey, 8, "0x1234/1_0x5679", nil)
	require.NoError(t, err)
	b, err = store.Builder(pubKey)
	require.NoError(t, err)
	require.Equal(t, uint64(8), b.LastSubmissionSlot)
	require.Equal(t, uint64(2), b.NumSubmissionsTotal)
	require.Equal(t, "0x1234/1_0x5679", b.LastSubmissionID)
	require.Greater(t, b.UpdatedAt, prevB.UpdatedAt)
	require.Equal(t, prevB.CreatedAt, b.CreatedAt)

	simErr := fmt.Errorf("sim error")
	err = store.UpsertBuilderSubmitted(pubKey2, 2, "0x1234/1_0x5678", simErr)
	require.NoError(t, err)
	b, err = store.Builder(pubKey2)
	require.NoError(t, err)
	require.Equal(t, uint64(2), b.LastSubmissionSlot)
	require.Equal(t, uint64(1), b.NumSubmissionsTotal)
	require.Equal(t, "0x1234/1_0x5678", b.LastSubmissionID)
	require.Equal(t, uint64(1), b.NumSubmissionsSimFailed)
	require.True(t, b.CreatedAt.After(now))
	require.True(t, b.UpdatedAt.After(now))

	prevB = b
	err = store.UpsertBuilderDelivered(pubKey2, 3, "0x1234/1_0x5678")
	require.NoError(t, err)
	b, err = store.Builder(pubKey2)
	require.NoError(t, err)
	require.Equal(t, uint64(3), b.LastDeliveredSlot)
	require.Equal(t, uint64(1), b.NumDeliveredTotal)
	require.Equal(t, "0x1234/1_0x5678", b.LastDeliveredID)
	require.True(t, b.UpdatedAt.After(prevB.UpdatedAt))
	require.Equal(t, prevB.CreatedAt, b.CreatedAt)

	err = store.UpsertBuilderDelivered(pubKey2, 9, "0x1234/1_0x5679")
	require.NoError(t, err)
	b, err = store.Builder(pubKey2)
	require.NoError(t, err)
	require.Equal(t, uint64(9), b.LastDeliveredSlot)
	require.Equal(t, uint64(2), b.NumDeliveredTotal)
	require.Equal(t, "0x1234/1_0x5679", b.LastDeliveredID)
	require.True(t, b.UpdatedAt.After(prevB.UpdatedAt))
	require.Equal(t, prevB.CreatedAt, b.CreatedAt)

	err = store.UpsertBuilderDelivered(pubKey3, 4, "0x1234/1_0x5678")
	require.NoError(t, err)
	b, err = store.Builder(pubKey3)
	require.NoError(t, err)
	require.Equal(t, uint64(4), b.LastDeliveredSlot)
	require.Equal(t, uint64(1), b.NumDeliveredTotal)
	require.Equal(t, "0x1234/1_0x5678", b.LastDeliveredID)
	require.True(t, b.CreatedAt.After(now))
	require.True(t, b.UpdatedAt.After(now))

	known, err := store.IsKnownBuilder(pubKey)
	require.NoError(t, err)
	require.True(t, known)

	known, err = store.IsKnownBuilder(types.PublicKey(random48Bytes()))
	require.Error(t, err)
	require.False(t, known)
}

func TestPebbleDBValidators(t *testing.T) {
	var (
		store, pths = newTestPebbleDB(t)
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
	)

	t.Cleanup(func() {
		store.Close()
		cleanupTestPebbleDB(t, pths)
	})

	_, err := store.Validator(validators[0].Message.Pubkey)
	require.Error(t, err)

	err = store.PutValidator(validators[0].Message.Pubkey, validators[0])
	require.NoError(t, err)
	v, err := store.Validator(validators[0].Message.Pubkey)
	require.NoError(t, err)
	require.Equal(t, &validators[0].SignedValidatorRegistration, v)

	err = store.PutValidator(validators[1].Message.Pubkey, validators[1])
	require.NoError(t, err)

	vs, err := store.Validators()
	require.NoError(t, err)
	require.Equal(t, 2, len(vs))
	require.Contains(t, vs, validators[0].SignedValidatorRegistration)
	require.Contains(t, vs, validators[1].SignedValidatorRegistration)

	c, err := store.CountValidators()
	require.NoError(t, err)
	require.Equal(t, uint64(2), c)
}

func TestPebbleDBDelivered(t *testing.T) {
	var (
		store, pths = newTestPebbleDB(t)
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
		store.Close()
		cleanupTestPebbleDB(t, pths)
	})

	p, err := store.Delivered(ProposerPayloadQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))

	for indx, payload := range payloads {
		if indx < 2 {
			eth1BlockHash32 := random32Bytes()
			eth1BlockHash := eth1BlockHash32[:]
			syncCommitte64 := random64Bytes()
			syncCommitte := syncCommitte64[:]
			err = store.PutDelivered(DeliveredPayload{
				BidTrace: payload.BidTrace,
				SignedBlindedBeaconBlock: &SignedBlindedBeaconBlock{
					Capella: &apicapella.SignedBlindedBeaconBlock{
						Message: &apicapella.BlindedBeaconBlock{
							Slot:          phase0.Slot(payload.Slot),
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
			err = store.PutDelivered(DeliveredPayload{
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

	p, err = store.Delivered(ProposerPayloadQuery{Slot: 1})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))

	p, err = store.Delivered(ProposerPayloadQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[0], p[0])

	p, err = store.Delivered(ProposerPayloadQuery{Slot: 2, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 2, len(p))
	require.Contains(t, p, payloads[1])
	require.Contains(t, p, payloads[2])

	p, err = store.Delivered(ProposerPayloadQuery{Slot: 2, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))

	p, err = store.Delivered(ProposerPayloadQuery{Cursor: 2, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 3, len(p))
	require.Equal(t, payloads[0], p[2])
	require.Contains(t, p, payloads[0])
	require.Contains(t, p, payloads[1])
	require.Contains(t, p, payloads[2])

	p, err = store.Delivered(ProposerPayloadQuery{ProposerPubkey: proposerKey, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 2, len(p))
	require.Equal(t, payloads[1], p[0])
	require.Equal(t, payloads[0], p[1])

	p, err = store.Delivered(ProposerPayloadQuery{BlockNumber: uint64(blockNum), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 3, len(p))
	require.Equal(t, payloads[3], p[0])
	require.Equal(t, payloads[2], p[1])
	require.Equal(t, payloads[0], p[2])

	p, err = store.Delivered(ProposerPayloadQuery{BlockHash: blockHash, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[1], p[0])

	p, err = store.Delivered(ProposerPayloadQuery{BlockHash: blockHash, BlockNumber: uint64(blockNum), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[1], p[0])

	p, err = store.Delivered(ProposerPayloadQuery{Slot: 2, ProposerPubkey: proposerKey, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[1], p[0])

	p, err = store.Delivered(ProposerPayloadQuery{Slot: 1, BlockNumber: uint64(blockNum), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, payloads[0], p[0])

	p, err = store.Delivered(ProposerPayloadQuery{Limit: 10, OrderBy: -1})
	require.NoError(t, err)
	require.Equal(t, 4, len(p))
	require.Equal(t, []BidTraceReceived{payloads[2], payloads[1], payloads[3], payloads[0]}, p)

	p, err = store.Delivered(ProposerPayloadQuery{Limit: 10, OrderBy: 1})
	require.NoError(t, err)
	require.Equal(t, 4, len(p))
	require.Equal(t, []BidTraceReceived{payloads[0], payloads[3], payloads[1], payloads[2]}, p)
}

func TestPebbleDBSubmitted(t *testing.T) {
	var (
		store, pths = newTestPebbleDB(t)
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
		store.Close()
		cleanupTestPebbleDB(t, pths)
	})

	p, err := store.Submitted(BuilderBlockQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))

	err = store.PutSubmitted(payloads[0])
	require.NoError(t, err)
	p, err = store.Submitted(BuilderBlockQuery{Slot: 1, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, BidTraceReceived{
		BidTrace:    payloads[0].BidTrace,
		Timestamp:   payloads[0].Timestamp.Unix(),
		TimestampMs: payloads[0].Timestamp.UnixMilli(),
	}, p[0])

	for _, p := range payloads[1:] {
		err = store.PutSubmitted(p)
		require.NoError(t, err)
	}

	p, err = store.Submitted(BuilderBlockQuery{Slot: 1, Limit: 10})
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

	p, err = store.Submitted(BuilderBlockQuery{Slot: 1, BlockNumber: uint64(payloads[1].BlockNumber), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(p))
	require.Equal(t, p[0], BidTraceReceived{
		BidTrace:    payloads[1].BidTrace,
		Timestamp:   payloads[1].Timestamp.Unix(),
		TimestampMs: payloads[1].Timestamp.UnixMilli(),
	})

	p, err = store.Submitted(BuilderBlockQuery{Slot: 2, Limit: 0})
	require.NoError(t, err)
	require.Equal(t, 0, len(p))
}

func TestPebbleDBBuilderBids(t *testing.T) {
	var (
		store, pths = newTestPebbleDB(t)
		slot        = uint64(1)
		bidTrace    = BidTrace{
			BidTrace: types.BidTrace{
				Slot:           slot,
				BlockHash:      types.Hash(random32Bytes()),
				ParentHash:     types.Hash(random32Bytes()),
				ProposerPubkey: types.PublicKey(random48Bytes()),
			},
			BlockNumber: 1,
		}
		executed = &builderapi.VersionedExecutionPayload{
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
		}
		builderBid = &builderspec.VersionedSignedBuilderBid{
			Version: consensusspec.DataVersionCapella,
			Capella: &buildercapella.SignedBuilderBid{
				Message: &buildercapella.BuilderBid{
					Value:  uint256.NewInt(101),
					Pubkey: phase0.BLSPubKey(random48Bytes()),
					Header: &consensuscapella.ExecutionPayloadHeader{
						ParentHash:       phase0.Hash32(bidTrace.ParentHash),
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
		}
	)

	t.Cleanup(func() {
		store.Close()
		cleanupTestPebbleDB(t, pths)
	})

	err := store.PutBuilderBid(
		bidTrace,
		GetPayloadResponse{
			Capella: executed,
		},
		GetHeaderResponse{
			Capella: builderBid,
		},
		time.Now().UTC(),
	)
	require.NoError(t, err)

	_, err = store.BidTrace(slot, types.PublicKey(random48Bytes()), types.Hash(random32Bytes()))
	require.Error(t, err)

	_, err = store.Executed(slot, types.PublicKey(random48Bytes()), types.Hash(random32Bytes()))
	require.Error(t, err)

	_, err = store.BestBid(slot, types.Hash(random32Bytes()).String(), types.PublicKey(random48Bytes()).String())
	require.Error(t, err)

	bt, err := store.BidTrace(slot, bidTrace.ProposerPubkey, bidTrace.BlockHash)
	require.NoError(t, err)
	require.Equal(t, bidTrace, *bt)

	e, err := store.Executed(slot, bidTrace.ProposerPubkey, bidTrace.BlockHash)
	require.NoError(t, err)
	require.Equal(t, &GetPayloadResponse{
		Capella: executed,
	}, e)

	b, err := store.BestBid(slot, bidTrace.ParentHash.String(), bidTrace.ProposerPubkey.String())
	require.NoError(t, err)
	require.Equal(t, &GetHeaderResponse{
		Capella: builderBid,
	}, b)

	biggerValue := builderBid
	biggerValue.Capella.Message.Value = uint256.NewInt(102)

	err = store.PutBuilderBid(
		bidTrace,
		GetPayloadResponse{
			Capella: executed,
		},
		GetHeaderResponse{
			Capella: biggerValue,
		},
		time.Now().UTC().Add(-time.Hour),
	)
	require.NoError(t, err)

	bt, err = store.BidTrace(slot, bidTrace.ProposerPubkey, bidTrace.BlockHash)
	require.Error(t, err)
	require.Nil(t, bt)
	require.Equal(t, ErrBidTraceExpired, err)

	b, err = store.BestBid(slot, bidTrace.ParentHash.String(), bidTrace.ProposerPubkey.String())
	require.Error(t, err)
	require.Nil(t, b)
	require.Equal(t, ErrBestBidExpired, err)
}

func newTestPebbleDB(t *testing.T) (*pebbleDB, string) {
	pth := newTestStorePrefix()

	store, err := NewPebbleDB(pth, true)
	require.NoError(t, err)
	return store, pth
}

func cleanupTestPebbleDB(t *testing.T, prefix string) {
	err := os.RemoveAll(prefix)
	require.NoError(t, err)
}
