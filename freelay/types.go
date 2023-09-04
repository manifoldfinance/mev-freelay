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
	"math/big"
	"time"

	builderapi "github.com/attestantio/go-builder-client/api"
	buildercapella "github.com/attestantio/go-builder-client/api/capella"
	builderspec "github.com/attestantio/go-builder-client/spec"
	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-boost-utils/types"
)

var (
	ZeroU256   = types.IntToU256(0)
	ZeroBigInt = big.NewInt(0)

	CapellaForkVersionGoerli  = "0x03001020"
	CapellaForkVersionMainnet = "0x03000000"
)

type JSONError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type BidTrace struct {
	BlockNumber uint64 `json:"block_number,string"`
	NumTx       uint64 `json:"num_tx,string"`
	types.BidTrace
}

type BidTraceTimestamp struct {
	BidTrace
	Timestamp time.Time `json:"timestamp"`
}

type BidTraceReceived struct {
	BidTrace
	Timestamp   int64 `json:"timestamp,omitempty"`
	TimestampMs int64 `json:"timestamp_ms,string,omitempty"`
}

type BidTraceExtended struct {
	BidTrace
	Timestamp           time.Time       `json:"timestamp"`
	SimError            string          `json:"sim_error"`
	ExecutionPayloadKey string          `json:"execution_payload_key"`
	Signature           types.Signature `json:"signature"`
	IP                  string          `json:"ip,omitempty"`
}

type BidTraceArchived struct {
	Slot                 uint64              `json:"slot,string"`
	BuilderPubkey        types.PublicKey     `json:"builder_pubkey" ssz-size:"48"`
	ProposerPubkey       types.PublicKey     `json:"proposer_pubkey" ssz-size:"48"`
	ProposerFeeRecipient types.Address       `json:"proposer_fee_recipient" ssz-size:"20"`
	Value                types.U256Str       `json:"value" ssz-size:"32"`
	Signature            types.Signature     `json:"signature" ssz-size:"96"`
	Timestamp            int64               `json:"timestamp,omitempty"`
	SimError             string              `json:"sim_error,omitempty"`
	IP                   string              `json:"ip,omitempty"`
	ExecutedPayload      *GetPayloadResponse `json:"executed_payload,omitempty"`
}

type DeliveredPayload struct {
	BidTrace
	SignedBlindedBeaconBlock *SignedBlindedBeaconBlock `json:"signed_blinded_beacon_block"`
	Timestamp                time.Time                 `json:"timestamp"`
	IP                       string                    `json:"ip,omitempty"`
}

type MissedPayload struct {
	TimeIntoSlot   int64           `json:"time_into_slot"`
	SlotStart      uint64          `json:"slot_start"`
	Timestamp      time.Time       `json:"timestamp"`
	Slot           uint64          `json:"slot,string"`
	ProposerPubkey types.PublicKey `json:"proposer_pubkey" ssz-size:"48"`
	BlockHash      types.Hash      `json:"block_hash" ssz-size:"32"`
	IP             string          `json:"ip,omitempty"`
	Error          string          `json:"error,omitempty"`
	DeliveredError string          `json:"delivered_error,omitempty"`
}

type BuilderGetValidatorsResponseEntry struct {
	types.BuilderGetValidatorsResponseEntry
	ValidatorIndex uint64 `json:"validator_index,string"`
}

type ProposerPayloadQuery struct {
	Slot           uint64
	Cursor         uint64
	BlockHash      types.Hash
	BlockNumber    uint64
	ProposerPubkey types.PublicKey
	OrderBy        int8 // DESC = -1 = -value and ASC = 1 = value, 0
	Limit          uint64
}

func newProposerPayloadQuery() ProposerPayloadQuery {
	return ProposerPayloadQuery{
		Limit: 200,
	}
}

func (q ProposerPayloadQuery) IsValid() (bool, error) {
	if q.Slot != 0 && q.Cursor != 0 {
		return false, ErrSlotCursorConflict
	}

	if q.Limit > 200 {
		return false, ErrProposerLimit
	}

	return true, nil
}

type BuilderBlockQuery struct {
	Slot        uint64
	BlockHash   types.Hash
	BlockNumber uint64
	Limit       uint64
}

func newBuilderBlockQuery() BuilderBlockQuery {
	return BuilderBlockQuery{
		Limit: 500,
	}
}

func (b BuilderBlockQuery) isValid() bool {
	if b.Slot == 0 && (b.BlockHash == types.Hash{}) && b.BlockNumber == 0 {
		return false
	}

	if b.Limit > 500 {
		return false
	}

	return true
}

type BuilderBlockValidationRequest struct {
	BuilderSubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (b *BuilderBlockValidationRequest) MarshalJSON() ([]byte, error) {
	req, err := b.BuilderSubmitBlockRequest.MarshalJSON()
	if err != nil {
		return nil, err
	}

	g, err := json.Marshal(struct {
		RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
	}{
		RegisteredGasLimit: b.RegisteredGasLimit,
	})
	if err != nil {
		return nil, err
	}

	g[0] = ','
	return append(req[:len(req)-1], g...), nil
}

type BlockBuilder struct {
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
	BuilderPubkey           types.PublicKey `json:"builder_pubkey"`
	Description             string          `json:"description"`
	HighPriority            bool            `json:"high_priority"`
	Blacklisted             bool            `json:"blacklisted"`
	LastSubmissionSlot      uint64          `json:"last_submission_slot,string"`
	LastSubmissionID        string          `json:"last_submission_id"`
	LastDeliveredSlot       uint64          `json:"last_delivered_slot,string"`
	LastDeliveredID         string          `json:"last_delivered_id"`
	NumSubmissionsTotal     uint64          `json:"num_submissions_total,string"`
	NumSubmissionsSimFailed uint64          `json:"num_submissions_sim_failed,string"`
	NumDeliveredTotal       uint64          `json:"num_delivered_total,string"`
	FirstSubmissionAt       time.Time       `json:"first_submission_at"`
	FirstDeliveredAt        time.Time       `json:"first_delivered_at"`
	LastSubmissionAt        time.Time       `json:"last_submission_at"`
	LastDeliveredAt         time.Time       `json:"last_delivered_at"`
	FirstSubmissionSlot     uint64          `json:"first_submission_slot,string"`
	FirstDeliveredSlot      uint64          `json:"first_delivered_slot,string"`
	FirstSubmissionID       string          `json:"first_submission_id"`
	FirstDeliveredID        string          `json:"first_delivered_id"`
}

type BlockedValidator struct {
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Pubkey    types.PublicKey `json:"pubkey"`
	Blocked   bool            `json:"blocked"`
	Notes     []string        `json:"notes,omitempty"`
}

type SignedValidatorRegistrationExtended struct {
	types.SignedValidatorRegistration
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip,omitempty"`
}

type SignedBlindedBeaconBlock struct {
	Capella   *apicapella.SignedBlindedBeaconBlock
	Bellatrix *types.SignedBlindedBeaconBlock
}

func (s *SignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	if s.Bellatrix != nil {
		return json.Marshal(s.Bellatrix)
	}
	return nil, nil
}

func (s *SignedBlindedBeaconBlock) UnmarshalJSON(data []byte) error {
	c := new(apicapella.SignedBlindedBeaconBlock)
	if err := json.Unmarshal(data, c); err == nil {
		s.Capella = c
		return nil
	}

	b := new(types.SignedBlindedBeaconBlock)
	if err := json.Unmarshal(data, b); err != nil {
		return err
	}
	s.Bellatrix = b
	return nil
}

func (s *SignedBlindedBeaconBlock) Signature() types.Signature {
	if s.Capella != nil {
		return types.Signature(s.Capella.Signature)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Signature
	}
	return types.Signature{}
}

func (s *SignedBlindedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Slot
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) ProposerIndex() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.ProposerIndex)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.ProposerIndex
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) BlockHash() types.Hash {
	if s.Capella != nil {
		return types.Hash(s.Capella.Message.Body.ExecutionPayloadHeader.BlockHash)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockHash
	}
	return types.Hash{}
}

func (s *SignedBlindedBeaconBlock) BlockNumber() uint64 {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) Message() types.HashTreeRoot {
	if s.Capella != nil {
		return s.Capella.Message
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message
	}
	return nil
}

type SignedBeaconBlock struct {
	Capella *consensuscapella.SignedBeaconBlock
}

func (s *SignedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	return nil, ErrEmpty
}

func (s *SignedBeaconBlock) UnmarshalJSON(data []byte) error {
	c := new(consensuscapella.SignedBeaconBlock)
	if err := json.Unmarshal(data, c); err != nil {
		return err
	}

	s.Capella = c
	return nil
}

func (s *SignedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}

	return 0
}

type GetPayloadResponse struct {
	Capella *builderapi.VersionedExecutionPayload
}

func (g *GetPayloadResponse) MarshalJSON() ([]byte, error) {
	if g.Capella != nil {
		return json.Marshal(g.Capella)
	}
	return nil, ErrEmpty
}

func (g *GetPayloadResponse) UnmarshalJSON(data []byte) error {
	c := new(builderapi.VersionedExecutionPayload)
	if err := json.Unmarshal(data, c); err != nil {
		return err
	}

	g.Capella = c
	return nil
}

func (g *GetPayloadResponse) BlockHash() types.Hash {
	if g.Capella != nil {
		return types.Hash(g.Capella.Capella.BlockHash)
	}
	return types.Hash{}
}

func (g *GetPayloadResponse) NumTx() int {
	if g.Capella != nil {
		return len(g.Capella.Capella.Transactions)
	}
	return 0
}

type VersionedExecutedPayload struct {
	Capella   *builderapi.VersionedExecutionPayload `json:"capella,omitempty"`
	Timestamp time.Time                             `json:"timestamp"`
}

type BuilderBidHeaderResponse struct {
	Capella   *builderspec.VersionedSignedBuilderBid `json:"capella,omitempty"`
	Timestamp time.Time                              `json:"timestamp"`
}

func (b *BuilderBidHeaderResponse) Value() *big.Int {
	if b.Capella != nil {
		return b.Capella.Capella.Message.Value.ToBig()
	}
	return nil
}

type GetHeaderResponse struct {
	Capella *builderspec.VersionedSignedBuilderBid
}

func (h *GetHeaderResponse) MarshalJSON() ([]byte, error) {
	if h.Capella != nil {
		return json.Marshal(h.Capella)
	}
	return nil, ErrEmpty
}

func (h *GetHeaderResponse) UnmarshalJSON(data []byte) error {
	c := new(builderspec.VersionedSignedBuilderBid)
	if err := json.Unmarshal(data, c); err != nil {
		return err
	}
	h.Capella = c
	return nil
}

func (h *GetHeaderResponse) IsEmpty() bool {
	if h == nil {
		return true
	}
	if h.Capella != nil {
		return h.Capella.Capella == nil || h.Capella.Capella.Message == nil
	}
	return true
}

func (h *GetHeaderResponse) Value() *big.Int {
	if h.Capella != nil {
		return h.Capella.Capella.Message.Value.ToBig()
	}
	return nil
}

func (h *GetHeaderResponse) BlockHash() types.Hash {
	if h.Capella != nil {
		return types.Hash(h.Capella.Capella.Message.Header.BlockHash)
	}
	return types.Hash{}
}

type BuilderSubmitBlockRequest struct {
	Capella *buildercapella.SubmitBlockRequest
}

func (r *BuilderSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	if r.Capella != nil {
		return json.Marshal(r.Capella)
	}
	return nil, ErrEmpty
}

func (r *BuilderSubmitBlockRequest) UnmarshalJSON(data []byte) error {
	c := new(buildercapella.SubmitBlockRequest)
	if err := json.Unmarshal(data, c); err != nil {
		return err
	}
	r.Capella = c
	return nil
}

func (r *BuilderSubmitBlockRequest) IsEmpty() bool {
	if r.Capella != nil {
		return r.Capella.Message == nil || r.Capella.ExecutionPayload == nil
	}
	return true
}

func (r *BuilderSubmitBlockRequest) ExecutionPayloadBlockHash() types.Hash {
	if r.Capella != nil {
		return types.Hash(r.Capella.ExecutionPayload.BlockHash)
	}
	return types.Hash{}
}

func (r *BuilderSubmitBlockRequest) ExecutionPayloadParentHash() types.Hash {
	if r.Capella != nil {
		return types.Hash(r.Capella.ExecutionPayload.ParentHash)
	}
	return types.Hash{}
}

func (r *BuilderSubmitBlockRequest) ExecutionPayloadRandom() types.Hash {
	if r.Capella != nil {
		return types.Hash(r.Capella.ExecutionPayload.PrevRandao)
	}
	return types.Hash{}
}

func (r *BuilderSubmitBlockRequest) BlockNumber() uint64 {
	if r.Capella != nil {
		return r.Capella.ExecutionPayload.BlockNumber
	}
	return 0
}

func (r *BuilderSubmitBlockRequest) Signature() types.Signature {
	if r.Capella != nil {
		return types.Signature(r.Capella.Signature)
	}
	return types.Signature{}
}

func (r *BuilderSubmitBlockRequest) Message() *types.BidTrace {
	if r.Capella != nil {
		return &types.BidTrace{
			Slot:                 r.Capella.Message.Slot,
			BuilderPubkey:        types.PublicKey(r.Capella.Message.BuilderPubkey),
			ProposerPubkey:       types.PublicKey(r.Capella.Message.ProposerPubkey),
			ProposerFeeRecipient: types.Address(r.Capella.Message.ProposerFeeRecipient),
			BlockHash:            types.Hash(r.Capella.Message.BlockHash),
			ParentHash:           types.Hash(r.Capella.Message.ParentHash),
			GasLimit:             r.Capella.Message.GasLimit,
			GasUsed:              r.Capella.Message.GasUsed,
			Value:                uint256ToU256(r.Capella.Message.Value),
		}
	}
	return nil
}

func (r *BuilderSubmitBlockRequest) Timestamp() uint64 {
	if r.Capella != nil {
		return r.Capella.ExecutionPayload.Timestamp
	}
	return 0
}

func (r *BuilderSubmitBlockRequest) NumTx() int {
	if r.Capella != nil {
		return len(r.Capella.ExecutionPayload.Transactions)
	}
	return 0
}

func (r *BuilderSubmitBlockRequest) Withdrawals() []*consensuscapella.Withdrawal {
	if r.Capella != nil {
		return r.Capella.ExecutionPayload.Withdrawals
	}
	return nil
}

func (r *BuilderSubmitBlockRequest) Value() *big.Int {
	if r.Capella != nil {
		return r.Capella.Message.Value.ToBig()
	}
	return nil
}
