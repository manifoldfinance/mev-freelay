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
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	relay "github.com/manifoldfinance/mev-freelay/freelay"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/r3labs/sse/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestRelayServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var (
		beaconRoutes, tsse = mockBeaconHandlers()
		srv                = httptest.NewServer(beaconRoutes)
		port               = getFreePort()
		cfg                = httpConfig{
			Addr:            fmt.Sprintf(":%d", port),
			Network:         "goerli",
			Beacons:         []string{srv.URL},
			DBPth:           fmt.Sprintf("test_%d_db", rand.Int()),
			BlockSimURL:     "http://localhost:8454",
			MaxRateLimit:    60,
			ReadTimeout:     1500,
			ReadHeadTimeout: 600,
			WriteTimeout:    10,
			IdleTimeout:     3,
		}
		address      = fmt.Sprintf("http://localhost:%d/", port)
		beacon       = relay.NewMultiBeacon(cfg.Beacons, 20)
		builder      = relay.NewBuilderBlockSimulator(10*time.Second, "http://localhost:8454")
		store, _     = relay.NewPebbleDB(cfg.DBPth, false)
		known        = relay.NewKnownValidators()
		duty         = relay.NewDutyState()
		evtSender, _ = relay.NewEventSender(ctx, "http://eventsender.url")
		sk, bpk, _   = bls.GenerateNewKeypair()
		pk, _        = types.BlsPublicKeyToPublicKey(bpk)
		cfgRelay, _  = relay.NewRelayConfig(cfg.Network, cfg.BlockSimURL, &pk, sk)
		relaySvc, _  = relay.NewRelay(
			ctx,
			store,
			beacon,
			builder,
			known,
			duty,
			evtSender,
			cfgRelay,
			uint64(time.Now().Unix()),
			0,
			10, 60, 5, 3_000, 4_000, 10*1024*1024, 3, 100,
			false,
			trace.NewNoopTracerProvider().Tracer("relay"),
		)
		quit = make(chan struct{})
	)

	t.Cleanup(func() {
		tsse.Close()
		store.Close()
		testCleanup(t, cfg.DBPth)
		srv.Close()
		cancel()
	})

	go func() {
		server := relaySvc.HTTPServer(cfg.Addr, cfg.ReadTimeout, cfg.ReadHeadTimeout, cfg.WriteTimeout, cfg.IdleTimeout, cfg.MaxHeaderBytes)
		go func() {
			err := server.ListenAndServe()
			require.Error(t, err)
		}()

		for {
			<-quit
			server.Shutdown(ctx) // nolint:errcheck
		}
	}()

	err := waitUntilServerRunning(fmt.Sprintf("%seth/v1/builder/status", address))
	assert.NoError(t, err)
	if err == nil {
		doHTTPCheckRequest(t, http.MethodGet, fmt.Sprintf("%seth/v1/builder/status", address))
		doHTTPCheckRequest(t, http.MethodPost, fmt.Sprintf("%seth/v1/builder/validators", address))
		doHTTPCheckRequest(t, http.MethodGet, fmt.Sprintf("%seth/v1/builder/header/5228387/0xf25ef9288d57cd06f3a3c6096d279e391f9a29519c99f88456ae53399fe6c443/0x880d966d2fc3a8b26031fda62dcff55038ede76afa28b09ae9b96055458c38fd7f11724a844c6197d773e693dccbd6ab", address))
		doHTTPCheckRequest(t, http.MethodPost, fmt.Sprintf("%seth/v1/builder/blinded_blocks", address))

		doHTTPCheckRequest(t, http.MethodPost, fmt.Sprintf("%srelay/v1/builder/validators", address))
		doHTTPCheckRequest(t, http.MethodPost, fmt.Sprintf("%srelay/v1/builder/blocks", address))

		doHTTPCheckRequest(t, http.MethodGet, fmt.Sprintf("%srelay/v1/data/bidtraces/proposer_payload_delivered", address))
		doHTTPCheckRequest(t, http.MethodGet, fmt.Sprintf("%srelay/v1/data/bidtraces/builder_blocks_received", address))
		doHTTPCheckRequest(t, http.MethodGet, fmt.Sprintf("%srelay/v1/data/validator_registration", address))
	}
	// stop current server once tests are done
	close(quit)
	err = waitUntilServerStopped(fmt.Sprintf("%seth/v1/builder/status", address))
	require.NoError(t, err)
}

func TestGracefulShutdown(t *testing.T) {
	var (
		port        = getFreePort()
		relaySvc    = mockTimeoutRelay{}
		address     = fmt.Sprintf("http://localhost:%d/", port)
		str         string
		ctx, cancel = context.WithCancel(context.Background())
	)

	go func() {
		runRelayServer(ctx, fmt.Sprintf(":%d", port), 1500, 600, 10, 3, 60000, &relaySvc) // nolint:errcheck
	}()

	err := waitUntilServerRunning(fmt.Sprintf("%sstatus", address))
	require.NoError(t, err)

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	res, status, err := doHTTPRequest(http.MethodGet, fmt.Sprintf("%stimeout", address))
	require.NoError(t, err)
	require.NotEqual(t, http.StatusNotFound, status)
	_ = json.NewDecoder(res).Decode(&str)
	defer res.Close() //nolint:errcheck
	require.Equal(t, "timeout executed", str)
	err = waitUntilServerStopped(fmt.Sprintf("%sstatus", address))
	assert.NoError(t, err)
}

type mockTimeoutRelay struct{}

func (m *mockTimeoutRelay) HTTPServer(addr string, rt, rht, wt, it, mh uint64) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	mux.HandleFunc("/timeout", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
		json.NewEncoder(w).Encode("timeout executed") //nolint:errcheck
	})

	return &http.Server{Addr: addr, Handler: mux}
}

func (m *mockTimeoutRelay) Stop() {}

func doHTTPCheckRequest(t *testing.T, method string, address string) {
	res, status, err := doHTTPRequest(method, address)
	assert.NoError(t, err)
	if err == nil {
		defer res.Close() //nolint:errcheck
	}
	assert.NotEqual(t, http.StatusNotFound, status)
	assert.NotEqual(t, http.StatusServiceUnavailable, status)
}

func doHTTPRequest(method string, address string) (io.ReadCloser, int, error) {
	req, err := http.NewRequest(method, address, nil)
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, 0, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}

	return res.Body, res.StatusCode, nil
}

func checkIfServerRunning(address string) error {
	req, err := http.NewRequest(http.MethodGet, address, nil)
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		return errors.New("server not yet running")
	}
	return nil
}

func waitUntilServerRunning(address string) error {
	attempts := 10
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if attempts == 0 {
			return errors.New("server not running")
		}
		err := checkIfServerRunning(address)
		if err != nil {
			attempts--
			<-ticker.C
		} else {
			return nil
		}
	}
}

func waitUntilServerStopped(address string) error {
	attempts := 10
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if attempts == 0 {
			return errors.New("server still running")
		}
		err := checkIfServerRunning(address)
		if err == nil {
			attempts--
			<-ticker.C
		} else {
			return nil
		}
	}
}

func testCleanup(t *testing.T, prefix string) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			err := os.RemoveAll(filepath.Join(".", entry.Name()))
			require.NoError(t, err)
		}
	}

	require.NoError(t, err)
}

func mockBeaconHandlers() (*http.ServeMux, *sse.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/beacon/genesis", mockBeaconGenesisInfoHandler)
	mux.HandleFunc("/eth/v1/node/syncing", mockBeaconSyncingHandler)
	mux.HandleFunc("/eth/v1/config/fork_schedule", mockBeaconForkScheduleHandler)
	mux.HandleFunc("/eth/v1/validator/duties/proposer/0", mockBeaconProposerDutiesHandler(0))
	mux.HandleFunc("/eth/v1/validator/duties/proposer/1", mockBeaconProposerDutiesHandler(1))
	mux.HandleFunc("/eth/v1/beacon/states/0/validators?status=active,pending", mockBeaconValidatorsHandler)
	mux.HandleFunc("/eth/v1/beacon/states/0/randao", mockBeaconRandaoHandler)

	s := sse.New()

	mux.HandleFunc("/eth/v1/events", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		query.Add("stream", "topics")
		r.URL.RawQuery = query.Encode()
		s.ServeHTTP(w, r)
	})

	s.CreateStream("topics")

	return mux, s
}

func mockBeaconGenesisInfoHandler(w http.ResponseWriter, r *http.Request) {
	g := relay.GenesisResponse{
		Data: relay.GenesisInfo{
			GenesisTime:           1631457600,
			GenesisValidatorsRoot: "0x8a8e65ffd7eb67e29b307a7f6038e1a6b95edd6f3a636d1d854f9ffdb7f83b13",
			GenesisForkVersion:    "0x00000000",
		},
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(g) //nolint:errcheck
}

func mockBeaconSyncingHandler(w http.ResponseWriter, r *http.Request) {
	s := relay.SyncNodeResponse{
		Data: relay.SyncNode{
			HeadSlot:  uint64(0),
			IsSyncing: false,
		},
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(s) //nolint:errcheck
}

func mockBeaconProposerDutiesHandler(slot uint64) http.HandlerFunc {
	vpk := types.PublicKey{0x2}.PubkeyHex().String()
	p := relay.ProposerDutiesResponse{
		Data: []relay.ProposerDuty{
			{
				Pubkey:         vpk,
				Slot:           slot,
				ValidatorIndex: uint64(0),
			},
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(p) //nolint:errcheck
	}
}

func mockBeaconForkScheduleHandler(w http.ResponseWriter, r *http.Request) {
	f := relay.ForkScheduleResponse{
		Data: []relay.ForkSchedule{
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
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(f) //nolint:errcheck
}

func mockBeaconValidatorsHandler(w http.ResponseWriter, r *http.Request) {
	v := relay.KnownValidatorsResponse{
		Data: []relay.ValidatorResponseEntry{
			{
				Index:   uint64(1),
				Balance: int64(1),
				Status:  "active_ongoing",
				Validator: relay.ValidatorResponseValidatorData{
					Pubkey: types.PublicKey{0x4}.PubkeyHex().String(),
				},
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func mockBeaconRandaoHandler(w http.ResponseWriter, r *http.Request) {
	randao := relay.RandaoResponse{
		Data: relay.Randao{
			Randao: types.Hash{0x2}.String(),
		},
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(randao) //nolint:errcheck
}

func getFreePort() int {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		logger.Error(err, "failed to get free port")
		os.Exit(1)
	}
	defer listener.Close() //nolint:errcheck
	return listener.Addr().(*net.TCPAddr).Port
}
