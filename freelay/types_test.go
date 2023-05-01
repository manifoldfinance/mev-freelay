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
	"testing"

	buildercapella "github.com/attestantio/go-builder-client/api/capella"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec/altair"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignedBlindedBeaconBlock(t *testing.T) {
	hash := random32Bytes()
	g := &SignedBlindedBeaconBlock{
		Capella: &apicapella.SignedBlindedBeaconBlock{
			Signature: phase0.BLSSignature(random96Bytes()),
			Message: &apicapella.BlindedBeaconBlock{
				Slot:          1,
				ProposerIndex: 2,
				ParentRoot:    phase0.Root(random32Bytes()),
				StateRoot:     phase0.Root(random32Bytes()),
				Body: &apicapella.BlindedBeaconBlockBody{
					RANDAOReveal:      phase0.BLSSignature(random96Bytes()),
					ETH1Data:          &phase0.ETH1Data{},
					Graffiti:          random32Bytes(),
					ProposerSlashings: []*phase0.ProposerSlashing{},
					AttesterSlashings: []*phase0.AttesterSlashing{},
					Attestations:      []*phase0.Attestation{},
					Deposits:          []*phase0.Deposit{},
					VoluntaryExits:    []*phase0.SignedVoluntaryExit{},
					SyncAggregate:     &altair.SyncAggregate{},
					ExecutionPayloadHeader: &consensuscapella.ExecutionPayloadHeader{
						BlockHash: phase0.Hash32(hash),
					},
				},
			},
		},
	}

	assert.Equal(t, g.BlockHash().String(), types.Hash(hash).String())
}

func TestBuilderSubmitBlockRequestMessage(t *testing.T) {
	var (
		parentHash           = random32Bytes()
		blockHash            = random32Bytes()
		builderPubKey        = random48Bytes()
		proposerPubKey       = random48Bytes()
		proposerFeeRecipient = random20Bytes()
		gasLimit             = uint64(1000000)
		gasUsed              = uint64(200000)
		value                = []byte{0x28, 0x05} // 10245
		cvalue               = uint256.Int{}
		bvalue               = types.U256Str{}
	)

	// big ending order
	uint25V1Value := cvalue.SetBytes(value)
	//  little-endian order
	err := bvalue.FromSlice(reverseBytes(value))
	require.NoError(t, err)
	bid := buildercapella.SubmitBlockRequest{
		Message: &v1.BidTrace{
			Slot:                 1,
			ParentHash:           phase0.Hash32(parentHash),
			BlockHash:            phase0.Hash32(blockHash),
			BuilderPubkey:        phase0.BLSPubKey(builderPubKey),
			ProposerPubkey:       phase0.BLSPubKey(proposerPubKey),
			ProposerFeeRecipient: consensusbellatrix.ExecutionAddress(proposerFeeRecipient),
			GasLimit:             gasLimit,
			GasUsed:              gasUsed,
			Value:                uint25V1Value,
		},
		ExecutionPayload: &consensuscapella.ExecutionPayload{
			ParentHash:   phase0.Hash32(random32Bytes()),
			FeeRecipient: consensusbellatrix.ExecutionAddress(random20Bytes()),
			BlockHash:    phase0.Hash32(random32Bytes()),
			ExtraData:    []byte{},
			Timestamp:    uint64(12),
			Withdrawals:  []*consensuscapella.Withdrawal{},
			Transactions: []consensusbellatrix.Transaction{},
		},
		Signature: phase0.BLSSignature(random96Bytes()),
	}

	bellatrixBid := types.BidTrace{
		Slot:                 1,
		ParentHash:           types.Hash(parentHash),
		BlockHash:            types.Hash(blockHash),
		BuilderPubkey:        types.PublicKey(builderPubKey),
		ProposerPubkey:       types.PublicKey(proposerPubKey),
		ProposerFeeRecipient: types.Address(proposerFeeRecipient),
		GasLimit:             gasLimit,
		GasUsed:              gasUsed,
		Value:                bvalue,
	}

	bsbr := BuilderSubmitBlockRequest{
		Capella: &bid,
	}

	require.Equal(t, "10245", bvalue.BigInt().String())
	require.Equal(t, "10245", uint25V1Value.ToBig().String())
	require.Equal(t, "10245", bsbr.Message().Value.BigInt().String())
	require.Equal(t, bsbr.Message(), &bellatrixBid)

}
