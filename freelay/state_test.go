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
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func TestDutyState(t *testing.T) {
	var (
		pk             = types.PublicKey(random48Bytes())
		pk1            = types.PublicKey(random48Bytes())
		slot           = uint64(96)
		s              = NewDutyState()
		proposerDuties = []BuilderGetValidatorsResponseEntry{
			{
				BuilderGetValidatorsResponseEntry: types.BuilderGetValidatorsResponseEntry{
					Slot: slot,
					Entry: &types.SignedValidatorRegistration{
						Message: &types.RegisterValidatorRequestMessage{
							Pubkey: pk,
						},
						Signature: types.Signature(random96Bytes()),
					},
				},
				ValidatorIndex: 0,
			},
		}
		proposerDuties2 = []BuilderGetValidatorsResponseEntry{
			{
				BuilderGetValidatorsResponseEntry: types.BuilderGetValidatorsResponseEntry{
					Slot: slot + 1,
					Entry: &types.SignedValidatorRegistration{
						Message: &types.RegisterValidatorRequestMessage{
							Pubkey: pk1,
						},
						Signature: types.Signature(random96Bytes()),
					},
				},
				ValidatorIndex: 2,
			},
		}
	)

	s.Set(proposerDuties, slot)
	d := s.All()
	require.Len(t, d, 1)

	bs := s.BySlot(slot)
	require.Equal(t, bs.BuilderGetValidatorsResponseEntry.Entry.Message.Pubkey.String(), pk.String())

	s.mux.Lock()
	s.proposerDutyMap[slot] = &ProposerDutyData{
		BuilderGetValidatorsResponseEntry: BuilderGetValidatorsResponseEntry{
			BuilderGetValidatorsResponseEntry: types.BuilderGetValidatorsResponseEntry{
				Slot: slot,
				Entry: &types.SignedValidatorRegistration{
					Message: &types.RegisterValidatorRequestMessage{
						Pubkey: pk,
					},
					Signature: types.Signature(random96Bytes()),
				},
			},
		},
		Timestamp: time.Now().UTC().Add(-(DurationPerEpoch * 2)),
	}
	s.mux.Unlock()

	s.Set(proposerDuties2, slot+1)
	d = s.All()
	require.Len(t, d, 1)

	bs = s.BySlot(slot + 1)
	require.Equal(t, bs.BuilderGetValidatorsResponseEntry.Entry.Message.Pubkey.String(), pk1.String())

	bs = s.BySlot(slot + 2)
	require.Nil(t, bs)
}
