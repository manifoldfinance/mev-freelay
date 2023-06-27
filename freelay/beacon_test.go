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
	"net/http"
	"net/http/httptest"
	"testing"

	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/r3labs/sse/v2"
	"github.com/stretchr/testify/require"
)

func TestBeaconJoin(t *testing.T) {
	b := newBeacon("http://localhost:8080", 20)

	pth := b.join("foo")
	require.Equal(t, "http://localhost:8080/foo", pth)

	pth = b.join(fmt.Sprintf("foo?d=%d", 1234))
	require.Equal(t, "http://localhost:8080/foo?d=1234", pth)

	pth = b.join(fmt.Sprintf("/eth/v1/beacon/states/%d/randao", 123))
	require.Equal(t, "http://localhost:8080/eth/v1/beacon/states/123/randao", pth)
}

func TestBeaconValidators(t *testing.T) {
	h, _ := mockBeaconValidatorsHandler(func() {})
	srv := httptest.NewServer(h)
	t.Cleanup(func() {
		srv.Close()
	})

	beacon := newBeacon(srv.URL, 20)
	v, err := beacon.Validators(0)
	require.NoError(t, err)
	require.Equal(t, 1, len(v.Data))
}

func mockBeaconGenesisInfoHandler() (http.HandlerFunc, *GenesisResponse) {
	g := GenesisResponse{
		Data: GenesisInfo{
			GenesisTime: 1590832934,
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		httpJSONResponse(w, http.StatusOK, g)
	}, &g
}

func mockBeaconSyncingHandler(args ...any) (http.HandlerFunc, *SyncNodeResponse) {
	slot := uint64(0)
	if len(args) > 0 && args[0] != nil {
		slot = args[0].(uint64)
	}
	s := SyncNodeResponse{
		Data: SyncNode{
			HeadSlot:  slot,
			IsSyncing: false,
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		httpJSONResponse(w, http.StatusOK, s)
	}, &s
}

func mockBeaconForkScheduleHandler() (http.HandlerFunc, *ForkScheduleResponse) {
	f := ForkScheduleResponse{
		Data: []ForkSchedule{
			{
				PreviousVersion: "0x00001020",
				CurrentVersion:  "0x00001020",
				Epoch:           0,
			},
			{
				PreviousVersion: "0x01001020",
				CurrentVersion:  "0x02001020",
				Epoch:           0,
			},
			{
				PreviousVersion: "0x02001020",
				CurrentVersion:  "0x03001020",
				Epoch:           6,
			},
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		httpJSONResponse(w, http.StatusOK, f)
	}, &f
}

func mockBeaconProposerDutiesHandler(slot uint64, args ...any) (http.HandlerFunc, *ProposerDutiesResponse) {
	vpk := types.PublicKey(random48Bytes()).PubkeyHex().String()
	if len(args) > 0 && args[0] != nil {
		vpk = args[0].(string)
	}
	vIndex := int(0)
	if len(args) > 1 && args[1] != nil {
		vIndex = args[1].(int)
	}
	p := ProposerDutiesResponse{
		Data: []ProposerDuty{
			{
				Pubkey:         vpk,
				Slot:           slot,
				ValidatorIndex: uint64(vIndex),
			},
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		httpJSONResponse(w, http.StatusOK, p)
	}, &p
}

func mockBeaconValidatorsHandler(fn func(), args ...any) (http.HandlerFunc, *KnownValidatorsResponse) {
	vpk := types.PublicKey(random48Bytes()).PubkeyHex().String()
	if len(args) > 0 && args[0] != nil {
		vpk = args[0].(string)
	}

	v := KnownValidatorsResponse{
		Data: []ValidatorResponseEntry{
			{
				Index:   uint64(1),
				Balance: int64(1),
				Status:  "active_ongoing",
				Validator: ValidatorResponseValidatorData{
					Pubkey: vpk,
				},
			},
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		defer fn()
		httpJSONResponse(w, http.StatusOK, v)
	}, &v
}

func mockBeaconRandaoHandler() (http.HandlerFunc, *RandaoResponse) { // nolint: unused
	randao := RandaoResponse{
		Data: Randao{
			Randao: types.Hash(random32Bytes()).String(),
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		httpJSONResponse(w, http.StatusOK, randao)
	}, &randao
}

func mockBeaconWithdrawalsHandler() (http.HandlerFunc, *WithdrawalsResponse) { // nolint: unused
	withdrawals := WithdrawalsResponse{
		Data: WithdrawalsData{
			Withdrawals: []*consensuscapella.Withdrawal{
				{
					ValidatorIndex: 0,
					Index:          0,
					Amount:         0,
					Address:        consensusbellatrix.ExecutionAddress(random20Bytes()),
				},
			},
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		httpJSONResponse(w, http.StatusOK, withdrawals)
	}, &withdrawals
}

func mockBeaconPublishBlockHandler(fn func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fn()
	}
}

func mockBeaconHeadEventsHandler(slot uint64, sseSrv *sse.Server) (http.HandlerFunc, func(), *HeadEvent) {
	headEvent := HeadEvent{
		Slot:  slot,
		Block: types.Hash(random32Bytes()).String(),
		State: types.Hash(random32Bytes()).String(),
	}
	b, _ := json.Marshal(headEvent)

	h := func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		query.Add("stream", "topics")
		r.URL.RawQuery = query.Encode()
		sseSrv.ServeHTTP(w, r)
	}

	publish := func() {
		sseSrv.Publish("topics", &sse.Event{Data: b})
	}

	return h, publish, &headEvent

}

func createSseServer() *sse.Server {
	s := sse.New()
	s.CreateStream("topics")
	return s
}
