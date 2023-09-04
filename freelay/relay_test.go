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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	builderapi "github.com/attestantio/go-builder-client/api"
	buildercapella "github.com/attestantio/go-builder-client/api/capella"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	builderspec "github.com/attestantio/go-builder-client/spec"
	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	utilcapella "github.com/attestantio/go-eth2-client/util/capella"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/gorilla/mux"
	"github.com/holiman/uint256"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/r3labs/sse/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/atomic"
)

func TestRootHandler(t *testing.T) {
	s := newTestRelay(t, 0, nil)
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	h := http.HandlerFunc(s.rootHandler())
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	res, _ := io.ReadAll(rr.Body)
	assert.Equal(t, "MEV Freelay API", string(res))
}

func TestStatusHandler(t *testing.T) {
	s := newTestRelay(t, 96, nil)
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/eth/v1/builder/status", nil)
	h := http.HandlerFunc(s.statusHandler())
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	b, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	assert.Equal(t, []byte{}, b)
}

func TestRegisterValidatorHandler(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	var (
		sk, bpk, _ = bls.GenerateNewKeypair()
		pk, _      = types.BlsPublicKeyToPublicKey(bpk)
		mvh, _     = mockBeaconValidatorsHandler(func() {
			wg.Done()
		}, pk.PubkeyHex().String())
		mockHandlers = map[string]http.HandlerFunc{
			"/eth/v1/beacon/states/96/validators": mvh,
		}
		s   = newTestRelay(t, 96, mockHandlers)
		msg = &types.RegisterValidatorRequestMessage{
			FeeRecipient: types.Address(random20Bytes()),
			GasLimit:     15_000_000,
			Timestamp:    uint64(time.Now().Unix()),
			Pubkey:       pk,
		}
		sig, _ = types.SignMessage(msg, s.cfg.DomainBuilder, sk)
		m      = types.SignedValidatorRegistration{
			Message:   msg,
			Signature: sig,
		}
	)

	wg.Wait()
	time.Sleep(200 * time.Millisecond) // because storing data into db takes some time after the handler is called

	b, _ := json.Marshal([]types.SignedValidatorRegistration{m})
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/eth/v1/builder/validator", io.NopCloser(bytes.NewReader(b)))
	req.ContentLength = int64(len(b))
	h := http.HandlerFunc(s.registerValidatorHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	b, _ = io.ReadAll(rr.Body)
	assert.Equal(t, []byte{}, b)
	assert.Equal(t, "", rr.Body.String())

	time.Sleep(200 * time.Millisecond) // because storing data into db takes some time after the handler is called

	v, err := s.store.Validators()
	require.NoError(t, err)
	require.Equal(t, 1, len(v))
	require.Equal(t, m, v[0])
}

func TestBuilderHeaderHandlerCapella(t *testing.T) {
	var (
		slot       = uint64(96)
		s          = newTestRelay(t, slot, map[string]http.HandlerFunc{})
		parentHash = types.Hash(random32Bytes())
		pubKey     = types.PublicKey(random48Bytes())
		pth        = fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", slot, parentHash.String(), pubKey.String())
		bidTrace   = BidTrace{
			BidTrace: types.BidTrace{
				Slot:           slot,
				BlockHash:      types.Hash(random32Bytes()),
				ParentHash:     parentHash,
				ProposerPubkey: pubKey,
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
		builderBidHeaderResponse = BuilderBidHeaderResponse{
			Timestamp: time.Now().UTC(),
			Capella:   builderBid,
		}
	)

	err := s.store.PutBuilderBid(
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

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, pth, nil)
	h := mux.NewRouter()
	h.HandleFunc("/eth/v1/builder/header/{slot:[0-9]+}/{parentHash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}", s.builderHeaderHandler()).Methods(http.MethodGet)
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	bb, err := json.Marshal(builderBidHeaderResponse.Capella)
	require.NoError(t, err)
	require.Equal(t, string(bb)+"\n", rr.Body.String())
	var res builderspec.VersionedSignedBuilderBid
	err = json.NewDecoder(rr.Body).Decode(&res)
	require.NoError(t, err)
	require.Equal(t, builderBidHeaderResponse.Capella, &res)
}

func TestUnblindBlindedBlockHandlerCapella(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	bwg := sync.WaitGroup{}
	bwg.Add(1)

	var (
		sk, bpk, _ = bls.GenerateNewKeypair()
		pk, _      = types.BlsPublicKeyToPublicKey(bpk)
		slot       = uint64(96)
		mph0, _    = mockBeaconProposerDutiesHandler(slot, pk.PubkeyHex().String(), 1)
		mph1, _    = mockBeaconProposerDutiesHandler(slot+1, pk.PubkeyHex().String(), 1)
		mvh, _     = mockBeaconValidatorsHandler(func() {
			wg.Done()
		}, pk.PubkeyHex().String())
		mpb = mockBeaconPublishBlockHandler(func() {
			bwg.Done()
		})
		mockHandlers = map[string]http.HandlerFunc{
			"/eth/v1/validator/duties/proposer/3": mph0,
			"/eth/v1/validator/duties/proposer/4": mph1,
			"/eth/v1/beacon/states/0/validators":  mvh,
			"/eth/v1/beacon/states/96/validators": mvh,
			"/eth/v1/beacon/blocks":               mpb,
		}
		s     = newTestRelay(t, slot, mockHandlers)
		bh32  = random32Bytes()
		bh    = bh32[:]
		scb64 = random64Bytes()
		scb   = scb64[:]
		gpr   = VersionedExecutedPayload{
			Capella: &builderapi.VersionedExecutionPayload{
				Version: consensusspec.DataVersionCapella,
				Capella: &consensuscapella.ExecutionPayload{
					ExtraData:    []byte{},
					BlockHash:    phase0.Hash32(random32Bytes()),
					ParentHash:   phase0.Hash32(random32Bytes()),
					Withdrawals:  []*consensuscapella.Withdrawal{},
					Transactions: []consensusbellatrix.Transaction{},
				},
			},
			Timestamp: time.Now().UTC(),
		}

		txs       = utilbellatrix.ExecutionPayloadTransactions{Transactions: gpr.Capella.Capella.Transactions}
		txroot, _ = txs.HashTreeRoot()
		wxs       = utilcapella.ExecutionPayloadWithdrawals{Withdrawals: gpr.Capella.Capella.Withdrawals}
		wxroot, _ = wxs.HashTreeRoot()
		bbb       = &apicapella.BlindedBeaconBlock{
			Slot:          phase0.Slot(slot),
			ProposerIndex: phase0.ValidatorIndex(1),
			ParentRoot:    phase0.Root(random32Bytes()),
			StateRoot:     phase0.Root(random32Bytes()),
			Body: &apicapella.BlindedBeaconBlockBody{
				RANDAOReveal: phase0.BLSSignature(random96Bytes()),
				ETH1Data: &phase0.ETH1Data{
					DepositRoot:  phase0.Root(random32Bytes()),
					BlockHash:    bh,
					DepositCount: 1,
				},
				Graffiti:          random32Bytes(),
				ProposerSlashings: []*phase0.ProposerSlashing{},
				AttesterSlashings: []*phase0.AttesterSlashing{},
				Attestations:      []*phase0.Attestation{},
				Deposits:          []*phase0.Deposit{},
				VoluntaryExits:    []*phase0.SignedVoluntaryExit{},
				SyncAggregate: &altair.SyncAggregate{
					SyncCommitteeBits:      bitfield.Bitvector512(scb),
					SyncCommitteeSignature: phase0.BLSSignature(random96Bytes()),
				},
				ExecutionPayloadHeader: &consensuscapella.ExecutionPayloadHeader{
					BlockHash:        gpr.Capella.Capella.BlockHash,
					ParentHash:       gpr.Capella.Capella.ParentHash,
					ExtraData:        gpr.Capella.Capella.ExtraData,
					TransactionsRoot: txroot,
					WithdrawalsRoot:  wxroot,
				},
				BLSToExecutionChanges: []*consensuscapella.SignedBLSToExecutionChange{},
			},
		}
		sig, _ = types.SignMessage(bbb, s.cfg.DomainBeaconProposerCapella, sk)
		bt     = BidTrace{
			BidTrace: types.BidTrace{
				Slot:           slot,
				ParentHash:     types.Hash(random32Bytes()),
				BlockHash:      types.Hash(bbb.Body.ExecutionPayloadHeader.BlockHash),
				BuilderPubkey:  types.PublicKey(random48Bytes()),
				ProposerPubkey: pk,
				Value:          types.IntToU256(1),
			},
			BlockNumber: 1,
		}
		rvrm = &types.RegisterValidatorRequestMessage{
			FeeRecipient: types.Address(random20Bytes()),
			GasLimit:     15_000_000,
			Timestamp:    uint64(time.Now().Unix()),
			Pubkey:       pk,
		}
		sigV, _ = types.SignMessage(rvrm, s.cfg.DomainBuilder, sk)
		svr     = types.SignedValidatorRegistration{
			Signature: sigV,
			Message:   rvrm,
		}
		svrExtended = SignedValidatorRegistrationExtended{
			SignedValidatorRegistration: svr,
			Timestamp:                   time.Now().UTC(),
			IP:                          "0.0.1.5",
		}
		payload = struct {
			Message   *apicapella.BlindedBeaconBlock `json:"message"`
			Signature string                         `json:"signature"`
		}{
			Message:   bbb,
			Signature: sig.String(),
		}
		builderBid = &builderspec.VersionedSignedBuilderBid{
			Version: consensusspec.DataVersionCapella,
			Capella: &buildercapella.SignedBuilderBid{
				Message: &buildercapella.BuilderBid{
					Value:  uint256.NewInt(101),
					Pubkey: phase0.BLSPubKey(random48Bytes()),
					Header: &consensuscapella.ExecutionPayloadHeader{
						ParentHash:       phase0.Hash32(bt.ParentHash),
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
		body, _ = json.Marshal(payload)
	)

	wg.Wait()

	err := s.store.PutValidator(pk, svrExtended)
	require.NoError(t, err)

	err = s.store.PutBuilderBid(
		bt,
		GetPayloadResponse{
			Capella: gpr.Capella,
		},
		GetHeaderResponse{
			Capella: builderBid,
		},
		time.Now().UTC(),
	)
	require.NoError(t, err)

	err = s.updateProposerDuties(slot)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/eth/v1/builder/blinded_blocks", io.NopCloser(bytes.NewReader(body)))
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	h := http.HandlerFunc(s.unblindBlindedBlockHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var res builderapi.VersionedExecutionPayload
	err = json.NewDecoder(rr.Body).Decode(&res)
	require.NoError(t, err)
	require.Equal(t, gpr.Capella, &res)

	bwg.Wait()

	ebh := types.Hash(bbb.Body.ExecutionPayloadHeader.BlockHash)
	ls, lb := s.latestDeliveredPayloadState.Get()
	require.Equal(t, slot, ls)
	require.Equal(t, &ebh, lb)

	time.Sleep(200 * time.Millisecond)

	b, err := s.store.Builder(bt.BuilderPubkey)
	require.NoError(t, err)
	require.Equal(t, slot, b.LastDeliveredSlot)

	d, err := s.store.Delivered(ProposerPayloadQuery{Slot: slot, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(d))
}

func TestPerEpochValidatorsHandler(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	var (
		sk, bpk, _ = bls.GenerateNewKeypair()
		pk, _      = types.BlsPublicKeyToPublicKey(bpk)
		slot       = uint64(96)
		mph0, _    = mockBeaconProposerDutiesHandler(slot, pk.PubkeyHex().String())
		mph1, _    = mockBeaconProposerDutiesHandler(slot+1, pk.PubkeyHex().String())
		mvh, _     = mockBeaconValidatorsHandler(func() {
			wg.Done()
		}, pk.PubkeyHex().String())
		mpb          = mockBeaconPublishBlockHandler(func() {})
		mockHandlers = map[string]http.HandlerFunc{
			"/eth/v1/validator/duties/proposer/3": mph0,
			"/eth/v1/validator/duties/proposer/4": mph1,
			"/eth/v1/beacon/states/0/validators":  mvh,
			"/eth/v1/beacon/states/96/validators": mvh,
			"/eth/v1/beacon/blocks":               mpb,
		}
		s    = newTestRelay(t, slot, mockHandlers)
		rvrm = &types.RegisterValidatorRequestMessage{
			FeeRecipient: types.Address(random20Bytes()),
			GasLimit:     15_000_000,
			Timestamp:    uint64(time.Now().Unix()),
			Pubkey:       pk,
		}
		sigV, _ = types.SignMessage(rvrm, s.cfg.DomainBuilder, sk)
		svr     = types.SignedValidatorRegistration{
			Signature: sigV,
			Message:   rvrm,
		}
		svrExtended = SignedValidatorRegistrationExtended{
			SignedValidatorRegistration: svr,
			Timestamp:                   time.Now().UTC(),
			IP:                          "0.0.3.4",
		}
	)

	wg.Wait()

	err := s.store.PutValidator(pk, svrExtended)
	require.NoError(t, err)
	err = s.updateProposerDuties(slot)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/eth/v1/builder/validators", nil)
	h := http.HandlerFunc(s.perEpochValidatorsHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var res []types.BuilderGetValidatorsResponseEntry
	err = json.NewDecoder(rr.Body).Decode(&res)
	require.NoError(t, err)
	require.Len(t, res, 2)
	require.Contains(t, res, types.BuilderGetValidatorsResponseEntry{Slot: slot, Entry: &svr})
	require.Contains(t, res, types.BuilderGetValidatorsResponseEntry{Slot: slot + 1, Entry: &svr})
}

func TestSubmitNewBlocksHandler(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	var (
		sk, bpk, _   = bls.GenerateNewKeypair()
		pk, _        = types.BlsPublicKeyToPublicKey(bpk)
		skp, bpkp, _ = bls.GenerateNewKeypair()
		pkp, _       = types.BlsPublicKeyToPublicKey(bpkp)
		slot         = uint64(96)
		mph0, _      = mockBeaconProposerDutiesHandler(slot, pk.PubkeyHex().String())
		mph1, _      = mockBeaconProposerDutiesHandler(slot+1, pk.PubkeyHex().String())
		mvh, _       = mockBeaconValidatorsHandler(func() {
			wg.Done()
		}, pk.PubkeyHex().String())
		withdrawals = []*consensuscapella.Withdrawal{
			{
				ValidatorIndex: 0,
				Index:          0,
				Amount:         0,
				Address:        consensusbellatrix.ExecutionAddress(random20Bytes()),
			},
		}
		randaoHash   = types.Hash(random32Bytes()).String()
		randao       types.Hash
		_            = randao.UnmarshalText([]byte(randaoHash))
		mockHandlers = map[string]http.HandlerFunc{
			"/eth/v1/validator/duties/proposer/3": mph0,
			"/eth/v1/validator/duties/proposer/4": mph1,
			"/eth/v1/beacon/states/0/validators":  mvh,
			"/eth/v1/beacon/states/96/validators": mvh,
		}
		s    = newTestRelay(t, slot, mockHandlers)
		rvrm = &types.RegisterValidatorRequestMessage{
			FeeRecipient: types.Address(random20Bytes()),
			GasLimit:     15_000_000,
			Timestamp:    uint64(time.Now().Unix()),
			Pubkey:       pk,
		}
		sigV, _ = types.SignMessage(rvrm, s.cfg.DomainBuilder, sk)
		svr     = types.SignedValidatorRegistration{
			Signature: sigV,
			Message:   rvrm,
		}
		svrExtended = SignedValidatorRegistrationExtended{
			SignedValidatorRegistration: svr,
			Timestamp:                   time.Now().UTC(),
			IP:                          "0.0.8.7",
		}
		bidCapella = &v1.BidTrace{
			Slot:                 slot + 1,
			ParentHash:           phase0.Hash32(random32Bytes()),
			BlockHash:            phase0.Hash32(random32Bytes()),
			BuilderPubkey:        phase0.BLSPubKey(pkp),
			ProposerPubkey:       phase0.BLSPubKey(pk),
			ProposerFeeRecipient: consensusbellatrix.ExecutionAddress(rvrm.FeeRecipient),
			Value:                uint256.NewInt(2983),
			GasLimit:             15_000_000,
			GasUsed:              879,
		}
		psigCapella, _ = types.SignMessage(bidCapella, s.cfg.DomainBuilder, skp)
		payloadCapella = struct {
			Message          *v1.BidTrace                       `json:"message"`
			ExecutionPayload *consensuscapella.ExecutionPayload `json:"execution_payload"`
			Signature        string                             `json:"signature"`
		}{
			Message: bidCapella,
			ExecutionPayload: &consensuscapella.ExecutionPayload{
				ParentHash:    bidCapella.ParentHash,
				FeeRecipient:  bidCapella.ProposerFeeRecipient,
				BlockHash:     bidCapella.BlockHash,
				ExtraData:     []byte{},
				Timestamp:     uint64(s.genesisTime + (slot+1)*SecondsPerSlot),
				Withdrawals:   withdrawals,
				Transactions:  []consensusbellatrix.Transaction{[]byte{0x01, 0x02, 0x03}},
				PrevRandao:    randao,
				StateRoot:     random32Bytes(),
				LogsBloom:     random256Bytes(),
				BlockNumber:   123,
				GasLimit:      bidCapella.GasLimit,
				GasUsed:       bidCapella.GasUsed,
				BaseFeePerGas: random32Bytes(),
			},
			Signature: psigCapella.String(),
		}
		bodyCapella, _    = json.Marshal(payloadCapella)
		payloadAttributes = PayloadAttributesEvent{
			Version: "capella",
			Data: PayloadAttributesEventData{
				ProposerIndex:     120,
				ProposalSlot:      slot + 1,
				ParentBlockNumber: 0,
				ParentBlockHash:   bidCapella.ParentHash.String(),
				ParentBlockRoot:   types.Hash(random32Bytes()).String(),
				PayloadAttributes: PayloadAttributes{
					Timestamp:             uint64(s.genesisTime + (slot+1)*SecondsPerSlot),
					PrevRandao:            randaoHash,
					SuggestedFeeRecipient: types.Address(random20Bytes()).String(),
					Withdrawals:           withdrawals,
				},
			},
		}
	)

	// bidCapella2 := bidCapella
	// bidCapella2.Value = uint256.NewInt(2984)
	// psigCapella2, _ := types.SignMessage(bidCapella2, s.cfg.DomainBuilder, skp)
	// payloadCapella2 := payloadCapella
	// payloadCapella2.Message = bidCapella2
	// payloadCapella2.Signature = psigCapella2.String()
	// bodyCapella2, _ := json.Marshal(payloadCapella2)

	bidCapella3 := bidCapella
	bidCapella3.Value = uint256.NewInt(2985)
	psigCapella3, _ := types.SignMessage(bidCapella3, s.cfg.DomainBuilder, skp)
	payloadCapella3 := payloadCapella
	payloadCapella3.Message = bidCapella3
	payloadCapella3.Signature = psigCapella3.String()
	bodyCapella3, _ := json.Marshal(payloadCapella3)

	bidCapella4 := bidCapella
	bidCapella4.Value = uint256.NewInt(2986)
	psigCapella4, _ := types.SignMessage(bidCapella4, s.cfg.DomainBuilder, skp)
	payloadCapella4 := payloadCapella
	payloadCapella4.Message = bidCapella4
	payloadCapella4.Signature = psigCapella4.String()
	bodyCapella4, _ := json.Marshal(payloadCapella4)

	bidCapella5 := bidCapella
	bidCapella5.Value = uint256.NewInt(2987)
	psigCapella5, _ := types.SignMessage(bidCapella5, s.cfg.DomainBuilder, skp)
	payloadCapella5 := payloadCapella
	payloadCapella5.Message = bidCapella5
	payloadCapella5.Signature = psigCapella5.String()

	wg.Wait()

	err := s.store.PutValidator(pk, svrExtended)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// we do it manually so we dont have to sleep
	err = s.updateProposerDuties(slot)
	require.NoError(t, err)
	err = s.processPayloadAttributes(payloadAttributes)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/eth/v1/builder/blocks", io.NopCloser(bytes.NewReader(bodyCapella)))
	h := http.HandlerFunc(s.submitNewBlockHandler(newRateLimiter(1, 1)))
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	b, _ := io.ReadAll(rr.Body)
	require.Equal(t, []byte{}, b)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/eth/v1/builder/blocks", io.NopCloser(bytes.NewReader(bodyCapella3)))
	h = http.HandlerFunc(s.submitNewBlockHandler(newRateLimiter(1, 1)))
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	b, _ = io.ReadAll(rr.Body)
	require.Equal(t, []byte{}, b)

	// octet content type but JSON body
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/eth/v1/builder/blocks", io.NopCloser(bytes.NewReader(bodyCapella4)))
	req.Header.Set("Content-Type", "application/octet-stream")
	h = http.HandlerFunc(s.submitNewBlockHandler(newRateLimiter(1, 1)))
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	b, _ = io.ReadAll(rr.Body)
	require.Equal(t, []byte{}, b)

	// octet
	sszData := &buildercapella.SubmitBlockRequest{
		Message:          payloadCapella5.Message,
		ExecutionPayload: payloadCapella5.ExecutionPayload,
		Signature:        phase0.BLSSignature(psigCapella5),
	}
	sszBytes, err := sszData.MarshalSSZ()
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/eth/v1/builder/blocks", bytes.NewBuffer(sszBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	h = http.HandlerFunc(s.submitNewBlockHandler(newRateLimiter(1, 1)))
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	b, _ = io.ReadAll(rr.Body)
	require.Equal(t, []byte{}, b)
}

func TestPayloadDeliveredHandler(t *testing.T) {
	var (
		slot = uint64(96)
		pk   = types.PublicKey(random48Bytes())
		s    = newTestRelay(t, slot, map[string]http.HandlerFunc{})
		bts  = []BidTrace{
			{
				BidTrace: types.BidTrace{
					Slot:           slot,
					ParentHash:     types.Hash(random32Bytes()),
					BlockHash:      types.Hash(random32Bytes()),
					BuilderPubkey:  types.PublicKey(random48Bytes()),
					ProposerPubkey: types.PublicKey(random48Bytes()),
					Value:          types.IntToU256(1),
				},
				BlockNumber: 1,
			},
			{
				BidTrace: types.BidTrace{
					Slot:           slot + 1,
					ParentHash:     types.Hash(random32Bytes()),
					BlockHash:      types.Hash(random32Bytes()),
					BuilderPubkey:  types.PublicKey(random48Bytes()),
					ProposerPubkey: pk,
					Value:          types.IntToU256(33),
				},
				BlockNumber: 3,
			},
			{
				BidTrace: types.BidTrace{
					Slot:           slot + 2,
					ParentHash:     types.Hash(random32Bytes()),
					BlockHash:      types.Hash(random32Bytes()),
					BuilderPubkey:  types.PublicKey(random48Bytes()),
					ProposerPubkey: types.PublicKey(random48Bytes()),
					Value:          types.IntToU256(77),
				},
				BlockNumber: 5,
			},
			{
				BidTrace: types.BidTrace{
					Slot:           slot,
					ParentHash:     types.Hash(random32Bytes()),
					BlockHash:      types.Hash(random32Bytes()),
					BuilderPubkey:  types.PublicKey(random48Bytes()),
					ProposerPubkey: pk,
					Value:          types.IntToU256(77),
				},
				BlockNumber: 5,
			},
			{
				BidTrace: types.BidTrace{
					Slot:           slot,
					ParentHash:     types.Hash(random32Bytes()),
					BlockHash:      types.Hash(random32Bytes()),
					BuilderPubkey:  types.PublicKey(random48Bytes()),
					ProposerPubkey: types.PublicKey(random48Bytes()),
					Value:          types.IntToU256(77),
				},
				BlockNumber: 5,
			},
		}
	)

	for _, b := range bts {
		bh32 := random32Bytes()
		bh := bh32[:]
		scb64 := random64Bytes()
		scb := scb64[:]
		err := s.store.PutDelivered(DeliveredPayload{
			BidTrace: b,
			SignedBlindedBeaconBlock: &SignedBlindedBeaconBlock{
				Capella: &apicapella.SignedBlindedBeaconBlock{
					Message: &apicapella.BlindedBeaconBlock{
						Slot:          phase0.Slot(b.Slot),
						ProposerIndex: phase0.ValidatorIndex(1),
						ParentRoot:    phase0.Root(random32Bytes()),
						StateRoot:     phase0.Root(random32Bytes()),
						Body: &apicapella.BlindedBeaconBlockBody{
							RANDAOReveal: phase0.BLSSignature(random96Bytes()),
							ETH1Data: &phase0.ETH1Data{
								DepositRoot:  phase0.Root(random32Bytes()),
								BlockHash:    bh,
								DepositCount: 1,
							},
							Graffiti:          random32Bytes(),
							ProposerSlashings: []*phase0.ProposerSlashing{},
							AttesterSlashings: []*phase0.AttesterSlashing{},
							Attestations:      []*phase0.Attestation{},
							Deposits:          []*phase0.Deposit{},
							VoluntaryExits:    []*phase0.SignedVoluntaryExit{},
							SyncAggregate: &altair.SyncAggregate{
								SyncCommitteeBits:      bitfield.Bitvector512(scb),
								SyncCommitteeSignature: phase0.BLSSignature(random96Bytes()),
							},
							ExecutionPayloadHeader: &consensuscapella.ExecutionPayloadHeader{
								BlockHash:  phase0.Hash32(random32Bytes()),
								ParentHash: phase0.Hash32(random32Bytes()),
							},
							BLSToExecutionChanges: []*consensuscapella.SignedBLSToExecutionChange{},
						},
					},
				},
			},
			Timestamp: time.Now().UTC(),
		})
		require.NoError(t, err)
	}

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "relay/v1/data/bidtraces/proposer_payload_delivered", nil)
	h := http.HandlerFunc(s.deliveredPayloadHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("relay/v1/data/bidtraces/proposer_payload_delivered?slot=%d", slot), nil)
	h = http.HandlerFunc(s.deliveredPayloadHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var res []BidTrace
	err := json.NewDecoder(rr.Body).Decode(&res)
	require.NoError(t, err)
	require.Len(t, res, 3)
	for _, b := range bts {
		if b.Slot == slot {
			require.Contains(t, res, b)
		}
	}
}

func TestSubmissionPayloadHandler(t *testing.T) {
	var (
		slot = uint64(96)
		pk   = types.PublicKey(random48Bytes())
		bh   = types.Hash(random32Bytes())
		s    = newTestRelay(t, slot, map[string]http.HandlerFunc{})
		btes = []BidTraceExtended{
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:           slot,
						BlockHash:      bh,
						ProposerPubkey: pk,
					},
					BlockNumber: 1,
				},
				Timestamp: time.Now().UTC(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:           slot,
						BlockHash:      types.Hash(random32Bytes()),
						ProposerPubkey: pk,
					},
					BlockNumber: 2,
				},
				Timestamp: time.Now().UTC(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:           slot + 2,
						BlockHash:      types.Hash(random32Bytes()),
						ProposerPubkey: pk,
					},
					BlockNumber: 2,
				},
				Timestamp: time.Now().UTC(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:           slot + 1,
						BlockHash:      types.Hash(random32Bytes()),
						ProposerPubkey: pk,
					},
					BlockNumber: 3,
				},
				Timestamp: time.Now().UTC(),
			},
			{
				BidTrace: BidTrace{
					BidTrace: types.BidTrace{
						Slot:           slot + 1,
						BlockHash:      types.Hash(random32Bytes()),
						ProposerPubkey: types.PublicKey(random48Bytes()),
					},
					BlockNumber: 5,
				},
				Timestamp: time.Now().UTC(),
			},
		}
	)

	for _, bte := range btes {
		err := s.store.PutSubmitted(bte)
		require.NoError(t, err)
	}

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "relay/v1/data/bidtraces/builder_blocks_received", nil)
	h := http.HandlerFunc(s.submissionPayloadHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("relay/v1/data/bidtraces/builder_blocks_received?slot=%d", slot), nil)
	h = http.HandlerFunc(s.submissionPayloadHandler())
	h.ServeHTTP(rr, req)
	var res []BidTraceReceived
	err := json.NewDecoder(rr.Body).Decode(&res)
	require.NoError(t, err)
	require.Len(t, res, 2)
	for _, bte := range btes {
		if bte.Slot == slot {
			require.Contains(t, res, BidTraceReceived{
				BidTrace:    bte.BidTrace,
				Timestamp:   bte.Timestamp.Unix(),
				TimestampMs: bte.Timestamp.UnixMilli(),
			})
		}
	}
}

func TestRegisteredValidatorHandler(t *testing.T) {
	var (
		slot       = uint64(96)
		sk, bpk, _ = bls.GenerateNewKeypair()
		pk, _      = types.BlsPublicKeyToPublicKey(bpk)
		s          = newTestRelay(t, slot, map[string]http.HandlerFunc{})
		rvrm       = &types.RegisterValidatorRequestMessage{
			FeeRecipient: types.Address(random20Bytes()),
			GasLimit:     15_000_000,
			Timestamp:    uint64(time.Now().Unix()),
			Pubkey:       pk,
		}
		sigV, _ = types.SignMessage(rvrm, s.cfg.DomainBuilder, sk)
		svr     = types.SignedValidatorRegistration{
			Signature: sigV,
			Message:   rvrm,
		}
		svrExtended = SignedValidatorRegistrationExtended{
			SignedValidatorRegistration: svr,
			Timestamp:                   time.Now().UTC(),
			IP:                          "0.1.3.5",
		}
	)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "relay/v1/data/validator_registration", nil)
	h := http.HandlerFunc(s.registeredValidatorHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	var jserr JSONError
	err := json.NewDecoder(rr.Body).Decode(&jserr)
	require.NoError(t, err)
	require.Equal(t, JSONError{Code: http.StatusBadRequest, Message: "pubkey is required"}, jserr)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("relay/v1/data/validator_registration?pubkey=%s", pk.String()), nil)
	h = http.HandlerFunc(s.registeredValidatorHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	err = json.NewDecoder(rr.Body).Decode(&jserr)
	require.NoError(t, err)
	require.Equal(t, JSONError{Code: http.StatusBadRequest, Message: "failed to get validator"}, jserr)

	err = s.store.PutValidator(pk, svrExtended)
	require.NoError(t, err)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("relay/v1/data/validator_registration?pubkey=%s", pk.String()), nil)
	h = http.HandlerFunc(s.registeredValidatorHandler())
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var res types.SignedValidatorRegistration
	err = json.NewDecoder(rr.Body).Decode(&res)
	require.NoError(t, err)
	require.Equal(t, svr, res)
}

func TestSse(t *testing.T) {
	s := sse.New()
	defer s.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/events", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		query.Add("stream", "topics")
		r.URL.RawQuery = query.Encode()
		s.ServeHTTP(w, r)
	})
	server := httptest.NewServer(mux)

	t.Cleanup(func() {
		server.Close()
	})

	s.CreateStream("topics")

	events := make(chan *sse.Event)
	var cErr error
	go func() {
		c := sse.NewClient(server.URL + "/eth/v1/events?topics=head")
		cErr = c.SubscribeRaw(func(msg *sse.Event) {
			if msg.Data != nil {
				events <- msg
				return
			}
		})
		if cErr != nil {
			time.Sleep(1 * time.Second)
		}
	}()

	// Wait for subscriber to be registered and message to be published
	time.Sleep(time.Millisecond * 200)
	require.Nil(t, cErr)
	s.Publish("topics", &sse.Event{Data: []byte("test")})
	msg := <-events
	assert.Equal(t, []byte(`test`), msg.Data)
}

func TestVerifySignature(t *testing.T) {
	sk, spk, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	pk, err := types.BlsPublicKeyToPublicKey(spk)
	require.NoError(t, err)

	v := &types.RegisterValidatorRequestMessage{
		FeeRecipient: types.Address{0x42},
		GasLimit:     15_000_000,
		Timestamp:    1652369368,
		Pubkey:       types.PublicKey{0x0d},
	}
	domain, err := computeDomain(types.DomainTypeAppBuilder, types.GenesisForkVersionGoerli, types.Root{}.String())
	require.NoError(t, err)

	sig, err := types.SignMessage(v, domain, sk)
	require.NoError(t, err)

	ok, err := types.VerifySignature(v, domain, pk[:], sig[:])
	require.NoError(t, err)
	require.True(t, ok)

	domain, err = computeDomain(types.DomainTypeBeaconProposer, CapellaForkVersionGoerli, types.GenesisValidatorsRootGoerli)
	require.NoError(t, err)

	b := &types.BlindedBeaconBlock{
		Body: &types.BlindedBeaconBlockBody{
			Eth1Data:               &types.Eth1Data{},
			ProposerSlashings:      []*types.ProposerSlashing{},
			AttesterSlashings:      []*types.AttesterSlashing{},
			Attestations:           []*types.Attestation{},
			Deposits:               []*types.Deposit{},
			VoluntaryExits:         []*types.SignedVoluntaryExit{},
			SyncAggregate:          &types.SyncAggregate{},
			ExecutionPayloadHeader: &types.ExecutionPayloadHeader{},
		},
	}
	sig, err = types.SignMessage(b, domain, sk)
	require.NoError(t, err)

	ok, err = types.VerifySignature(b, domain, pk[:], sig[:])
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRefreshKnownValidators(t *testing.T) {
	var (
		h, v   = mockBeaconValidatorsHandler(func() {})
		srv    = httptest.NewServer(h)
		beacon = NewMultiBeacon([]string{srv.URL}, 20)
		s      = relay{
			beacon:         beacon,
			knownValidator: NewKnownValidators(),
			headSlot:       *atomic.NewUint64(0),
			log:            logger.WithValues("test", t.Name()),
		}
	)

	s.headSlot.Store(uint64(16))
	t.Cleanup(func() {
		srv.Close()
	})

	err := s.refreshKnownValidators()
	require.NoError(t, err)

	ok := s.knownValidator.IsKnown(types.PubkeyHex(v.Data[0].Validator.Pubkey))
	require.True(t, ok)
}

func TestStartLoopProcessNewSlot(t *testing.T) {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	var (
		prefix           = fmt.Sprintf("test.%d", rand.Int())
		slot             = uint64(96)
		sk, bpk, _       = bls.GenerateNewKeypair()
		pk, _            = types.BlsPublicKeyToPublicKey(bpk)
		sseSrv           = createSseServer()
		mbhe, publish, _ = mockBeaconHeadEventsHandler(slot, sseSrv)
		mbp0, _          = mockBeaconProposerDutiesHandler(slot, pk.PubkeyHex().String())
		mbp1, _          = mockBeaconProposerDutiesHandler(slot+1, pk.PubkeyHex().String())
	)

	defer sseSrv.Close()

	wg := &sync.WaitGroup{}
	wg.Add(2)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/eth/v1/events", mbhe)
	mux.HandleFunc("/eth/v1/validator/duties/proposer/3", func(w http.ResponseWriter, r *http.Request) {
		mbp0(w, r)
		wg.Done()
	})
	mux.HandleFunc("/eth/v1/validator/duties/proposer/4", func(w http.ResponseWriter, r *http.Request) {
		mbp1(w, r)
		wg.Done()
	})

	var (
		srv      = httptest.NewServer(mux)
		beacon   = NewMultiBeacon([]string{srv.URL}, 20)
		store, _ = NewPebbleDB(prefix, false)
		cfg, _   = NewRelayConfig("goerli", "http://localhost:8080", &pk, sk)
		s        = relay{
			beacon:           beacon,
			dutyState:        NewDutyState(),
			store:            store,
			randaoState:      newRandaoState(),
			withdrawalsState: newWithdrawalsState(),
			knownValidator:   NewKnownValidators(),
			cfg:              cfg,
			headSlot:         *atomic.NewUint64(0),
			log:              logger.WithValues("test", t.Name()),
			ctx:              context.Background(),
		}
		rvrm = &types.RegisterValidatorRequestMessage{
			FeeRecipient: types.Address(random20Bytes()),
			GasLimit:     15_000_000,
			Timestamp:    uint64(time.Now().Unix()),
			Pubkey:       pk,
		}
		sigV, _   = types.SignMessage(rvrm, s.cfg.DomainBuilder, sk)
		validator = types.SignedValidatorRegistration{
			Signature: sigV,
			Message:   rvrm,
		}
		validatorExtended = SignedValidatorRegistrationExtended{
			SignedValidatorRegistration: validator,
			IP:                          "1.2.3.5",
			Timestamp:                   time.Now().UTC(),
		}
	)

	t.Cleanup(func() {
		store.Close()
		cleanupTestPebbleDB(t, prefix)
		srv.Close()
	})

	time.Sleep(time.Millisecond * 500)

	err := s.store.PutValidator(pk, validatorExtended)
	require.NoError(t, err)

	go s.startLoopProcessNewSlot()
	publish()

	wg.Wait()
	time.Sleep(time.Second * 1)

	require.Equal(t, slot, s.headSlot.Load())

	proposerDutiesResponse := s.dutyState.All()
	proposerDutiesSlot := s.dutyState.Slot()

	require.Equal(t, slot, proposerDutiesSlot)
	require.Len(t, proposerDutiesResponse, 2)
}

func TestLatestDeliveredPayloadState(t *testing.T) {
	l := newLatestDeliveredPayloadState()
	require.Equal(t, uint64(0), l.slot)
	require.Nil(t, l.blockHash)

	l.Set(1, types.Hash{0x01})
	require.Equal(t, uint64(1), l.slot)
	require.Equal(t, &types.Hash{0x01}, l.blockHash)

	l.Set(2, types.Hash{0x02})
	s, bh := l.Get()
	require.Equal(t, uint64(2), s)
	require.Equal(t, &types.Hash{0x02}, bh)
}

func newTestRelay(t *testing.T, slot uint64, genesisMocks map[string]http.HandlerFunc) *relay {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	ctx, cancel := context.WithCancel(context.Background())

	var (
		epoch   = slot / SlotsPerEpoch
		mgh, _  = mockBeaconGenesisInfoHandler()
		msh, _  = mockBeaconSyncingHandler(slot)
		mfh, _  = mockBeaconForkScheduleHandler()
		mph0, _ = mockBeaconProposerDutiesHandler(slot)
		mph1, _ = mockBeaconProposerDutiesHandler(slot + 1)
		mvh, _  = mockBeaconValidatorsHandler(func() {})
		mpb     = mockBeaconPublishBlockHandler(func() {})
		mocks   = map[string]http.HandlerFunc{
			"/eth/v1/beacon/genesis":                                     mgh,
			"/eth/v1/node/syncing":                                       msh,
			"/eth/v1/config/fork_schedule":                               mfh,
			fmt.Sprintf("/eth/v1/validator/duties/proposer/%d", epoch):   mph0,
			fmt.Sprintf("/eth/v1/validator/duties/proposer/%d", epoch+1): mph1,
			fmt.Sprintf("/eth/v1/beacon/states/%d/validators", slot):     mvh,
			"/eth/v1/beacon/blocks":                                      mpb,
		}
		store, prefix = newTestPebbleDB(t)
		mux           = http.NewServeMux()
		known         = NewKnownValidators()
		duty          = NewDutyState()
		sk, bpk, _    = bls.GenerateNewKeypair()
		pk, _         = types.BlsPublicKeyToPublicKey(bpk)
		simSrv        = mockSimGethSrv()
		cfg, _        = NewRelayConfig("goerli", simSrv.URL, &pk, sk)
		evtSender, _  = NewEventSender(ctx, "http://eventsender.url")
		genesis       = uint64(time.Now().Add(-time.Hour).Unix())
	)

	// extend default mocks
	for url, h := range genesisMocks {
		mocks[url] = h
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	// populate mux with mocks
	for url, h := range mocks {
		mux.HandleFunc(url, h)
	}
	ls := sse.New()
	mux.HandleFunc("/eth/v1/events", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		query.Add("stream", "topics")
		r.URL.RawQuery = query.Encode()
		ls.ServeHTTP(w, r)
	})
	beaconSrv := httptest.NewServer(mux)
	ls.CreateStream("topics")

	beacon := NewMultiBeacon([]string{beaconSrv.URL}, 20)
	builder := NewBuilderBlockSimulator(time.Duration(10*time.Second), simSrv.URL)

	s, err := NewRelay(
		ctx,
		store,
		beacon,
		builder,
		known,
		duty,
		evtSender,
		cfg,
		genesis,
		slot,
		1_000, 60, 5, 10_000_000, 10_000_000, 10*1024*1024, 3, 100,
		false,
		trace.NewNoopTracerProvider().Tracer("relay"),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		cancel()
		time.Sleep(100 * time.Millisecond)
		ls.Close()
		beaconSrv.Close()
		simSrv.Close()
		store.Close()
		cleanupTestPebbleDB(t, prefix)
	})

	return s
}

func mockSimGethSrv() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpJSONResponse(w, http.StatusOK, jsonrpcMessage{
			Version: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  "flashbots_validateBuilderSubmissionV2",
			Result:  json.RawMessage(`{"status": "ok"}`),
		})
	}))
	return srv
}
