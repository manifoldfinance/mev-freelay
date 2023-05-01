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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	builderapi "github.com/attestantio/go-builder-client/api"
	buildercapella "github.com/attestantio/go-builder-client/api/capella"
	builderspec "github.com/attestantio/go-builder-client/spec"
	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	utilcapella "github.com/attestantio/go-eth2-client/util/capella"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/julienschmidt/httprouter"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/rs/cors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/atomic"
	"golang.org/x/exp/slices"
)

const (
	SlotsPerEpoch           = 32
	SecondsPerSlot          = 12
	DurationPerSlot         = time.Second * SecondsPerSlot
	DurationPerEpoch        = DurationPerSlot * time.Duration(SlotsPerEpoch)
	activeValidatorTimespan = 3 * time.Hour

	getPayloadRetryMS = 100
)

var (
	ethV1BuilderSlotRgx    = regexp.MustCompile("^[0-9]+$")
	ethV1BuilderHashRgx    = regexp.MustCompile("^0x[a-fA-F0-9]+$")
	ignoreGetHeaderHeaders = []string{"mev-boost/v1.5.0 Go-http-client/1.1"}
)

type Relay interface {
	HTTPServer(addr string, readTimeout, readHeadTimeout, writeTimeout, idleTimeout uint64) *http.Server
}

type relay struct {
	store                     StoreSetter
	beacon                    MultiBeacon
	knownValidator            KnownValidatorSetter
	activeValidator           ActiveValidatorSetter
	dutyState                 DutySetter
	cfg                       *RelayConfig
	evtSender                 EventSender
	genesisTime               uint64
	pprofAPI                  bool
	maxRateLimit              uint64
	tracer                    trace.Tracer
	traceIP                   bool
	beaconProposeTimeout      time.Duration
	cutOffTimeout             uint64
	allowBuilderCancellations bool

	headSlot             atomic.Uint64
	isUpdatingPropDuties atomic.Bool
	randaoState          *randaoState
	withdrawalsState     *withdrawalsState
}

func NewRelay(store StoreSetter, beacon MultiBeacon, known KnownValidatorSetter, active ActiveValidatorSetter, duty DutySetter, evtSender EventSender, cfg *RelayConfig, genesis uint64, pprofAPI bool, maxRateLimit uint64, beaconProposeTimeout time.Duration, cutOffTimeout uint64, traceIP, allowBuilderCancellations bool, tracer trace.Tracer) (*relay, error) {
	syncNode, err := beacon.BestSyncingNode()
	if err != nil {
		return nil, err
	}

	r := &relay{
		store:                     store,
		beacon:                    beacon,
		knownValidator:            known,
		activeValidator:           active,
		dutyState:                 duty,
		cfg:                       cfg,
		evtSender:                 evtSender,
		genesisTime:               genesis,
		pprofAPI:                  pprofAPI,
		maxRateLimit:              maxRateLimit,
		tracer:                    tracer,
		beaconProposeTimeout:      beaconProposeTimeout,
		cutOffTimeout:             cutOffTimeout,
		traceIP:                   traceIP,
		allowBuilderCancellations: allowBuilderCancellations,
		randaoState:               newRandaoState(),
		withdrawalsState:          newWithdrawalsState(),
	}

	headSlot := syncNode.Data.HeadSlot
	logger.Info("initial update proposer duties", "headSlot", headSlot)
	if err := r.updateProposerDuties(headSlot); err != nil {
		logger.Error(err, "failed to update proposer duties", "headSlot", headSlot)
		return nil, err
	}

	logger.Info("processing current slot", "headSlot", headSlot)
	if err := r.processNewSlot(headSlot); err != nil {
		logger.Error(err, "failed to process current slot", "headSlot", headSlot)
	}

	logger.Info("start refreshing known validators")
	go r.startRefreshKnownValidators()

	logger.Info("start loop processing of new slots")
	go r.startLoopProcessNewSlot()

	logger.Info("start loop to process new payload attributes")
	go r.startLoopProcessPayloadAttributes()

	logger.Info("start loop to cleanup active validators")
	go r.startLoopCleanupActiveValidators()

	return r, nil
}

func (s *relay) HTTPServer(addr string, readTimeout, readHeadTimeout, writeTimeout, idleTimeout uint64) *http.Server {
	mux := s.routes()
	handler := cors.Default().Handler(mux)

	srv := http.Server{
		Addr:    addr,
		Handler: handler,

		ReadTimeout:       time.Duration(readTimeout) * time.Millisecond,
		ReadHeaderTimeout: time.Duration(readHeadTimeout) * time.Millisecond,
		WriteTimeout:      time.Duration(writeTimeout) * time.Second,
		IdleTimeout:       time.Duration(idleTimeout) * time.Second,
	}

	return &srv
}

// @contact.name   Manifold Finance, Inc.
// @contact.url    https://www.manifoldfinance.com/

// @license.name The Universal Permissive License (UPL), Version 1.0
// @license.url https://oss.oracle.com/licenses/upl/
// @title Freelay API
// @version 1.0
// @description Specification for the Freelay API.
// @host localhost:50051
// @BasePath /
func (s *relay) routes() *httprouter.Router {
	mux := httprouter.New()
	// root
	mux.HandlerFunc(http.MethodGet, "/", wrapper(s.rootHandler()))

	// proposer endpoints
	mux.HandlerFunc(http.MethodGet, "/eth/v1/builder/status", wrapper(s.statusHandler()))
	mux.HandlerFunc(http.MethodPost, "/eth/v1/builder/validators", wrapper(s.registerValidatorHandler()))
	mux.HandlerFunc(http.MethodGet, "/eth/v1/builder/header/:slot/:parentHash/:pubKey", wrapper(s.builderHeaderHandler()))
	mux.HandlerFunc(http.MethodPost, "/eth/v1/builder/blinded_blocks", wrapper(s.unblindBlindedBlockHandler()))

	// builder endpoints
	mux.HandlerFunc(http.MethodGet, "/relay/v1/builder/validators", wrapper(s.perEpochValidatorsHandler()))
	mux.HandlerFunc(http.MethodPost, "/relay/v1/builder/blocks", wrapper(s.submitNewBlockHandler(newRateLimiter(s.maxRateLimit, DurationPerEpoch)))) // X requests per key

	// data endpoints
	mux.HandlerFunc(http.MethodGet, "/relay/v1/data/bidtraces/proposer_payload_delivered", wrapper(s.deliveredPayloadHandler()))
	mux.HandlerFunc(http.MethodGet, "/relay/v1/data/bidtraces/builder_blocks_received", wrapper(s.submissionPayloadHandler()))
	mux.HandlerFunc(http.MethodGet, "/relay/v1/data/validator_registration", wrapper(s.registeredValidatorHandler()))

	// tracing endpoints
	if s.pprofAPI {
		mux.HandlerFunc(http.MethodGet, "/debug/pprof", pprof.Index)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/symbol", pprof.Symbol)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/trace", pprof.Trace)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/profile", pprof.Profile)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/heap", pprof.Handler("heap").ServeHTTP)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
		mux.HandlerFunc(http.MethodGet, "/debug/pprof/block", pprof.Handler("block").ServeHTTP)
	}

	mux.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		httpJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	})

	return mux
}

func (s *relay) startRefreshKnownValidators() {
	ticker := time.NewTicker(DurationPerEpoch / 2)
	for {
		logger.Info("refreshing known validators")
		if err := s.refreshKnownValidators(); err != nil {
			logger.Error(err, "failed to refresh known validators")
		}
		<-ticker.C
	}
}

func (s *relay) startLoopProcessNewSlot() {
	evt := make(chan HeadEvent)

	logger.Info("subscribing to head events")
	s.beacon.SubscribeToHeadEvents(evt)

	for {
		e := <-evt
		logger.Info("received new head event", "headSlot", e.Slot)
		if err := s.processNewSlot(e.Slot); err != nil {
			logger.Error(err, "failed to process new slot", "headSlot", e.Slot)
		}
	}
}

func (s *relay) startLoopProcessPayloadAttributes() {
	evt := make(chan PayloadAttributesEvent)

	logger.Info("subscribing to payload attributes events")
	s.beacon.SubscribeToPayloadAttributesEvents(evt)

	for {
		e := <-evt
		logger.Info("received new payload attributes event")
		if err := s.processPayloadAttributes(e); err != nil {
			logger.Error(err, "failed to process payload attributes")
		}
	}
}

func (s *relay) startLoopCleanupActiveValidators() {
	active, err := s.store.ActiveValidatorsStats()
	if err != nil {
		logger.Error(err, "failed to get active validator stats from store")
	} else {
		s.activeValidator.Set(active)
	}

	ticker := time.NewTicker(DurationPerEpoch)
	for {
		logger.Info("cleaning up active validator stats")
		s.activeValidator.ClearOld()
		av := s.activeValidator.Get()
		if err := s.store.SetActiveValidatorsStats(av); err != nil {
			logger.Error(err, "failed to update active validator stats in store")
		}
		<-ticker.C
	}
}

func (s *relay) updateProposerDuties(headSlot uint64) error {
	if s.isUpdatingPropDuties.Swap(true) {
		return nil
	}
	defer s.isUpdatingPropDuties.Store(false)

	epochFrom := headSlot / uint64(SlotsPerEpoch)
	epochTo := epochFrom + 1

	log := logger.WithValues(
		"method", "updateProposerDuties",
		"headSlot", headSlot,
		"epochFrom", epochFrom,
		"epochTo", epochTo,
		"receivedAt", time.Now().UTC(),
	)

	currentEpoch, err := s.beacon.ProposerDuties(epochFrom)
	if err != nil {
		return err
	}

	nextEpoch, err := s.beacon.ProposerDuties(epochTo)
	if err != nil {
		return err
	}

	entries := append(currentEpoch.Data, nextEpoch.Data...)

	proposerDuties := make([]BuilderGetValidatorsResponseEntry, 0)
	unregisteredValidators := make([]types.PublicKey, 0)
	for _, entry := range entries {
		pubkey := new(types.PublicKey)
		_ = pubkey.UnmarshalText([]byte(entry.Pubkey))
		validator, err := s.store.RegisteredValidator(*pubkey)
		if err != nil {
			unregisteredValidators = append(unregisteredValidators, *pubkey)
			continue
		}

		proposerDuties = append(proposerDuties, BuilderGetValidatorsResponseEntry{
			BuilderGetValidatorsResponseEntry: types.BuilderGetValidatorsResponseEntry{
				Slot:  entry.Slot,
				Entry: validator,
			},
			ValidatorIndex: entry.ValidatorIndex,
		})
	}

	log.Info("setting proposer duties", "numProposerDuties", len(proposerDuties), "numEntries", len(entries), "unregisteredValidators", len(unregisteredValidators))
	s.dutyState.Set(proposerDuties, headSlot)

	return nil
}

func (s *relay) processNewSlot(headSlot uint64) error {
	logger.Info("processing new slot", "headSlot", headSlot)
	prevHeadSlot := s.headSlot.Load()
	if headSlot <= prevHeadSlot {
		return fmt.Errorf("slot %d is older than current head slot %d", headSlot, prevHeadSlot)
	}

	if prevHeadSlot > 0 {
		for i := prevHeadSlot + 1; i < headSlot; i++ {
			logger.Info("missed slot", "slot", i, "prevHeadSlot", prevHeadSlot, "headSlot", headSlot)
		}
	}

	s.headSlot.Store(headSlot)

	go func() {
		logger.Info("updating proposer duties", "headSlot", headSlot, "prevHeadSlot", prevHeadSlot)
		if err := s.updateProposerDuties(headSlot); err != nil {
			logger.Error(err, "failed to update proposer duties", "headSlot", headSlot, "prevHeadSlot", prevHeadSlot)
		}
	}()

	go func() {
		logger.Info("storing latest slot", "headSlot", headSlot, "prevHeadSlot", prevHeadSlot)
		if err := s.store.SetLatestSlotStats(headSlot); err != nil {
			logger.Error(err, "failed to store latest slot", "headSlot", headSlot, "prevHeadSlot", prevHeadSlot)
		}
	}()

	return nil
}

func (s *relay) processPayloadAttributes(e PayloadAttributesEvent) error {
	headSlot := s.headSlot.Load()
	proposalSlot := e.Data.ProposalSlot

	if proposalSlot <= headSlot {
		return fmt.Errorf("skipping old payload attributes: proposalSlot=%d headSlot=%d", proposalSlot, headSlot)
	}

	log := logger.WithValues(
		"method", "processPayloadAttributes",
		"proposalSlot", proposalSlot,
		"headSlot", headSlot,
	)

	s.randaoState.mux.Lock()
	defer s.randaoState.mux.Unlock()

	prevRandao := e.Data.PayloadAttributes.PrevRandao
	s.randaoState.expectedPrevRandao = &randaoHelper{
		slot:       proposalSlot,
		prevRandao: prevRandao,
	}
	log.Info("updated expected randao", "prevRandao", prevRandao)

	withdrawals := e.Data.PayloadAttributes.Withdrawals
	root, err := computeWithdrawalsRoot(withdrawals)
	if err != nil {
		log.Error(err, "failed to compute withdrawals root")
	}

	s.withdrawalsState.mux.Lock()
	defer s.withdrawalsState.mux.Unlock()

	s.withdrawalsState.expectedRoot = &withdrawalsHelper{
		slot: proposalSlot,
		root: root,
	}
	log.Info("updated expected withdrawals", "root", root)

	return nil
}

func (s *relay) refreshKnownValidators() error {
	validators, err := s.beacon.Validators(s.headSlot.Load())
	if err != nil {
		return err
	}

	vHexs := make(map[types.PubkeyHex]struct{})
	vByIndx := make(map[uint64]types.PubkeyHex)
	for _, v := range validators {
		vHexs[types.NewPubkeyHex(v.Validator.Pubkey)] = struct{}{}
		vByIndx[v.Index] = types.NewPubkeyHex(v.Validator.Pubkey)
	}

	s.knownValidator.Set(vHexs, vByIndx)

	return nil
}

func (s *relay) rootHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("PBS Relay API")) //nolint:errcheck
	}
}

// @Tags Proposer
// @Summary Health check
// @Description Get the health status of the relay server
// @Success 200
// @Router /eth/v1/builder/status [get]
func (s *relay) statusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// @Tags Proposer
// @Summary Register validators
// @Description Register or update validator's
// @Accept json
// @Produce json
// @Param body body []types.SignedValidatorRegistration true "Signed validator registration"
// @Success 200
// @Failure 400 {object} JSONError
// @Failure 500 {object} JSONError
// @Router /eth/v1/builder/validators [post]
func (s *relay) registerValidatorHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues(
			"method", "registerValidator",
			"userAgent", r.UserAgent(),
		)

		p := make([]types.SignedValidatorRegistration, 0)
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			log.Error(err, "failed to decode request body")
			httpJSONError(w, http.StatusBadRequest, "failed to decode request body")
			return
		}
		defer r.Body.Close() //nolint:errcheck

		_, span := s.tracer.Start(r.Context(), "registerValidator", trace.WithAttributes(attribute.Int("numValidators", len(p))))
		defer span.End()

		var ip string
		if s.traceIP {
			ip = userIP(r)
		}

		var (
			numFailedRegistrations     uint64
			numSuccessfulRegistrations uint64
			numActiveValidators        uint64
		)
		for _, v := range p {
			ok := s.knownValidator.IsKnown(v.Message.Pubkey.PubkeyHex())
			if !ok {
				numFailedRegistrations++
				log.Info("unknown validator", "pubkey", v.Message.Pubkey)
				continue
			}

			if v.Message.Timestamp > uint64(time.Now().Add(10*time.Second).Unix()) {
				numFailedRegistrations++
				log.Info("timestamp is too far in the future", "pubkey", v.Message.Pubkey)
				continue
			}

			prevValidator, err := s.store.RegisteredValidator(v.Message.Pubkey)
			if err != nil {
				log.Error(err, "failed to get validator", "pubkey", v.Message.Pubkey)
			} else if prevValidator.Message.Timestamp >= v.Message.Timestamp {
				numActiveValidators++
				s.activeValidator.Put(v.Message.Pubkey)
				continue
			}

			ok, err = types.VerifySignature(v.Message, s.cfg.DomainBuilder, v.Message.Pubkey[:], v.Signature[:])
			if !ok || err != nil {
				numFailedRegistrations++
				log.Error(err, "invalid signature", "msg", v.Message, "signature", v.Signature, "pubkey", v.Message.Pubkey)
				continue
			}

			validatorExtended := SignedValidatorRegistrationExtended{
				SignedValidatorRegistration: v,
				IP:                          ip,
				Timestamp:                   time.Now().UTC(),
			}
			if err := s.store.PutRegistrationValidator(v.Message.Pubkey, validatorExtended); err != nil {
				numFailedRegistrations++
				log.Error(err, "failed to put validator", "pubkey", v.Message.Pubkey)
				continue
			}

			numSuccessfulRegistrations++
			s.activeValidator.Put(v.Message.Pubkey)
		}

		log.Info("registered validators", "processed", len(p), "successful", numSuccessfulRegistrations, "active", numActiveValidators, "failed", numFailedRegistrations)

		if numSuccessfulRegistrations == 0 && numActiveValidators == 0 {
			log.Info("failed to register or validate any validators", "processed", len(p), "successful", numSuccessfulRegistrations, "active", numActiveValidators, "failed", numFailedRegistrations)
			httpJSONError(w, http.StatusBadRequest, "failed to register any validators")
			return
		}

		if numFailedRegistrations > 0 {
			log.Info("failed to register some validators", "processed", len(p), "successful", numSuccessfulRegistrations, "active", numActiveValidators, "failed", numFailedRegistrations)
			httpJSONError(w, http.StatusBadRequest, "failed to register some validators")
			return
		}

		log.Info("successful registration", "processed", len(p), "successful", numSuccessfulRegistrations, "active", numActiveValidators, "failed", numFailedRegistrations)
		w.WriteHeader(http.StatusOK)
	}
}

// @Tags Proposer
// @Summary Header
// @Description Get header response
// @Accept json
// @Produce json
// @Param slot path string true "Slot"
// @Param parentHash path string true "Parent hash"
// @Param pubKey path string true "Pubkey"
// @Success 200 {object} builderspec.VersionedSignedBuilderBid
// @Failure 400 {object} JSONError
// @Failure 500 {object} JSONError
// @Router /eth/v1/builder/header/{slot}/{parentHash}/{pubKey} [get]
func (s *relay) builderHeaderHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		receivedAt := time.Now().UTC()
		ua := r.UserAgent()

		log := logger.WithValues(
			"method", "getHeader",
			"userAgent", ua,
			"path", r.URL.Path,
			"receivedAt", receivedAt,
		)

		if slices.Contains(ignoreGetHeaderHeaders, ua) {
			log.Info("ignoring mev-boost/v1.5.0")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		hReceivedAt := r.Header.Get("X-Req-Received-At")
		if hReceivedAt != "" {
			milli, err := strconv.ParseInt(hReceivedAt, 10, 64)
			if err == nil {
				receivedAt = time.UnixMilli(milli).UTC()
			} else {
				log.Error(err, "failed to parse received at header")
			}
		} else {
			log.Info("received at header not found")
		}

		log = log.WithValues("receivedAt", receivedAt)

		_, span := s.tracer.Start(r.Context(), "getHeader", trace.WithAttributes(attribute.String("pth", r.URL.Path)))
		defer span.End()

		params := httprouter.ParamsFromContext(r.Context())
		slotStr := params.ByName("slot")
		parentHashStr := params.ByName("parentHash")
		pubKeyStr := params.ByName("pubKey")

		if slotStr == "" || parentHashStr == "" || pubKeyStr == "" {
			log.Error(errors.New("invalid path"), "url path is invalid", "path", r.URL.Path)
			httpJSONError(w, http.StatusBadRequest, "invalid path")
			return
		}

		if !ethV1BuilderSlotRgx.MatchString(slotStr) || !ethV1BuilderHashRgx.MatchString(parentHashStr) || !ethV1BuilderHashRgx.MatchString(pubKeyStr) {
			log.Error(errors.New("invalid path format"), "url path format is invalid", "slot", slotStr)
			httpJSONError(w, http.StatusBadRequest, "invalid path format")
			return
		}

		slot, err := strconv.ParseUint(slotStr, 10, 64)
		if err != nil {
			log.Error(err, "urls slot is invalid", "slot", slotStr)
			httpJSONError(w, http.StatusBadRequest, "invalid slot")
			return
		}

		parentHash := new(types.Hash)
		err = parentHash.UnmarshalText([]byte(strings.ToLower(parentHashStr)))
		if err != nil || len(parentHashStr) != 66 {
			log.Error(err, "invalid parent hash", "parentHash", parentHashStr)
			httpJSONError(w, http.StatusBadRequest, "invalid parent hash")
			return
		}

		pubkey := new(types.PublicKey)
		err = pubkey.UnmarshalText([]byte(strings.ToLower(pubKeyStr)))
		if err != nil || len(pubKeyStr) != 98 {
			log.Error(err, "invalid pubkey", "pubkey", pubKeyStr)
			httpJSONError(w, http.StatusBadRequest, "invalid pubkey")
			return
		}

		headSlot := s.headSlot.Load()
		if slot < headSlot {
			log.Error(errors.New("slot is too old"), "provided slot is too old", "slot", slot, "headSlot", headSlot)
			httpJSONError(w, http.StatusBadRequest, "slot is too old")
			return
		}

		if slot > headSlot+1 {
			log.Error(errors.New("slot is too new"), "provided slot is too far ahead", "slot", slot, "headSlot", headSlot)
			httpJSONError(w, http.StatusBadRequest, "slot is too far ahead")
			return
		}

		slotStart := (s.genesisTime + slot*SecondsPerSlot) * 1000
		timeIntoSlot := receivedAt.UnixMilli() - int64(slotStart)
		if s.cutOffTimeout > 0 && timeIntoSlot > int64(s.cutOffTimeout) {
			log.Error(errors.New("too late to get header"), "too late to get header", "timeIntoSlot", timeIntoSlot, "cutOffTimeout", s.cutOffTimeout)
			httpJSONError(w, http.StatusBadRequest, "too late to get header")
			return
		}

		bid, err := s.store.BestBid(slot, *parentHash, *pubkey)
		if err != nil && err != ErrBestBidNotFound {
			log.Error(err, "failed to get bid")
			httpJSONError(w, http.StatusBadRequest, "failed to get bid")
			return
		}

		if bid.IsEmpty() {
			log.Info("no bid found")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if bid.Value().Cmp(ZeroBigInt) == 0 {
			log.Info("bid with no value")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		log.Info("found bid", "value", bid.Value(), "blockHash", bid.BlockHash())
		httpJSONResponse(w, http.StatusOK, bid)

		if err := s.evtSender.SendHeaderFetchedEvent(
			slot,
			gethcommon.Hash(bid.BlockHash()),
			bid.Value(),
		); err != nil {
			log.Error(err, "failed to send header fetched event to event bus")
		}
	}
}

// @Tags Proposer
// @Summary Unblind block
// @Description Unblind block
// @Accept json
// @Produce json
// @Param body body apicapella.SignedBlindedBeaconBlock true "Signed blinded beacon block"
// @Success 200 {object} builderapi.VersionedExecutionPayload
// @Failure 400 {object} JSONError
// @Failure 500 {object} JSONError
// @Router /eth/v1/builder/blinded_blocks [post]
func (s *relay) unblindBlindedBlockHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		receivedAt := time.Now().UTC()
		log := logger.WithValues(
			"method", "getPayload",
			"userAgent", r.UserAgent(),
			"receivedAt", receivedAt,
		)

		hReceivedAt := r.Header.Get("X-Req-Received-At")
		if hReceivedAt != "" {
			milli, err := strconv.ParseInt(hReceivedAt, 10, 64)
			if err == nil {
				receivedAt = time.UnixMilli(milli).UTC()
			} else {
				log.Error(err, "failed to parse received at header")
			}
		} else {
			log.Info("received at header not found")
		}

		log = log.WithValues("receivedAt", receivedAt)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error(err, "failed to read body")
			httpJSONError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		defer r.Body.Close() // nolint:errcheck

		payload := new(SignedBlindedBeaconBlock)
		capellaPayload := new(apicapella.SignedBlindedBeaconBlock)
		if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&capellaPayload); err != nil {
			log.Error(err, "failed to decode block to capella")
			httpJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}

		payload.Capella = capellaPayload

		_, span := s.tracer.Start(r.Context(), "getPayload", trace.WithAttributes(attribute.Int64("slot", int64(payload.Slot())), attribute.String("blockHash", payload.BlockHash().String())))
		defer span.End()

		log = log.WithValues(
			"slot", payload.Slot(),
			"blockHash", payload.BlockHash(),
			"query", r.URL.RawQuery,
		)

		slotDuty := s.dutyState.BySlot(payload.Slot())
		if slotDuty == nil {
			log.Error(errors.New("proposer not found"), "proposer not found")
		} else if slotDuty.ValidatorIndex != payload.ProposerIndex() {
			log.Error(errors.New("proposer index mismatch"), "proposer index mismatch", "slotDuty.ValidatorIndex", slotDuty.ValidatorIndex, "payload.ProposerIndex", payload.ProposerIndex())
			httpJSONError(w, http.StatusBadRequest, "proposer index mismatch")
			return
		}

		pbHex, err := s.knownValidator.ByIndex(payload.ProposerIndex())
		if err != nil {
			log.Error(err, "failed to get validator by index", "index", payload.ProposerIndex())
			httpJSONError(w, http.StatusBadRequest, "failed to get validator by index")
			return
		}

		pubKey, err := types.HexToPubkey(pbHex.String())
		if err != nil {
			log.Error(err, "failed to create a pubkey", "pubkey", pbHex)
			httpJSONError(w, http.StatusBadRequest, "failed to create a pubkey")
			return
		}

		sig := payload.Signature()
		ok, err := types.VerifySignature(payload.Message(), s.cfg.DomainBeaconProposerCapella, pubKey[:], sig[:])
		if !ok || err != nil {
			log.Error(err, "invalid signature for capella", "pubkey", pubKey, "ok", ok)
			httpJSONError(w, http.StatusBadRequest, "invalid signature")
			return
		}

		var (
			exErr  error
			res    *GetPayloadResponse
			ticker = time.NewTicker(time.Duration(getPayloadRetryMS) * time.Millisecond)
		)
		for i := 0; i < 3; i++ {
			res, exErr = s.store.ExecutedPayload(payload.Slot(), pubKey, payload.BlockHash())
			if exErr == nil {
				break
			}
			log.Info("retrying to get executed payload after 100ms because sometimes we get fetching for executed data even before it is written in the DB", "retry", i)
			// retry 3 times with 100ms delay in 2 attempts because sometimes we get fetching for executed data even before it is written in the DB
			if i == 2 {
				break
			}
			<-ticker.C
		}

		if exErr != nil {
			log.Error(exErr, "failed to get executed payload")
			httpJSONError(w, http.StatusBadRequest, "failed to get executed payload")
			return
		}

		lastSlot, err := s.store.LatestDeliveredSlotStats()
		if err != nil {
			log.Error(err, "failed to get last delivered slot")
		} else if payload.Slot() <= lastSlot {
			log.Error(errors.New("slot was already delivered"), "slot", payload.Slot(), "lastSlot", lastSlot)
			httpJSONError(w, http.StatusBadRequest, "slot was already delivered")
			return
		}

		go func() {
			if err := s.store.SetLatestDeliveredSlotStats(payload.Slot()); err != nil {
				log.Error(err, "failed to set latest slot stats")
			}
		}()

		slotStart := (s.genesisTime + payload.Slot()*SecondsPerSlot) * 1000
		timeIntoSlot := receivedAt.UnixMilli() - int64(slotStart)
		if timeIntoSlot < 0 {
			earlyMS := time.Now().UTC().UnixMilli() - int64(slotStart)
			if earlyMS < 0 {
				delayMS := earlyMS * -1
				log = log.WithValues("delayMS", delayMS)
				log.Info("delaying unblinding block because it is too early")
				time.Sleep(time.Duration(delayMS) * time.Millisecond)
			}
		} else if s.cutOffTimeout > 0 && timeIntoSlot > int64(s.cutOffTimeout) {
			log.Error(errors.New("too late to unblind block"), "too late to unblind block", "timeIntoSlot", timeIntoSlot, "cutOffTimeout", s.cutOffTimeout)
			httpJSONError(w, http.StatusBadRequest, "too late to unblind block")

			go func() {
				if err := s.store.PutMissedPayload(payload.Slot(), pubKey, payload.BlockHash(), MissedPayload{
					TimeIntoSlot: timeIntoSlot,
					Timestamp:    receivedAt,
					SlotStart:    slotStart,
				}); err != nil {
					log.Error(err, "failed to put missed payload")
				}
			}()
			return
		}

		if err := compareExecutionHeaderPayload(payload, res); err != nil {
			log.Error(err, "failed to compare execution header and payload")
			httpJSONError(w, http.StatusBadRequest, "failed to compare execution header and payload")
			return
		}

		unblindedBlock := unblindedSignedBeaconBlock(payload, res)
		startTime := time.Now().UTC()
		if err := s.beacon.PublishBlock(unblindedBlock); err != nil {
			log.Error(err, "failed to publish block")
			httpJSONError(w, http.StatusBadRequest, "failed to publish block")
			return
		}

		log.Info("block published", "slot", payload.Slot(), "blockHash", payload.BlockHash(), "duration", time.Since(startTime).Milliseconds())

		// wait for the block to be propagate over other p2p nodes
		time.Sleep(s.beaconProposeTimeout * time.Millisecond)

		var ip string
		if s.traceIP {
			ip = userIP(r)
		}
		go func() {
			bidTrace, err := s.store.BidTrace(payload.Slot(), pubKey, payload.BlockHash())
			if err != nil {
				log.Error(err, "failed to get bid trace payload")
			} else {
				log.Info("found bid trace", "bidTraceSlot", bidTrace.Slot, "bidTraceBlockHash", bidTrace.BlockHash, "bidTraceBuilderPubkey", bidTrace.BuilderPubkey, "bidTraceProposerPubkey", bidTrace.ProposerPubkey)
				if err := s.store.PutDeliveredPayload(DeliveredPayload{
					BidTrace:                 *bidTrace,
					SignedBlindedBeaconBlock: payload,
					Timestamp:                receivedAt,
					IP:                       ip,
				}); err != nil {
					log.Error(err, "failed to put delivered payload")
				}

				if err := s.store.UpsertBlockBuilderDeliveredPayload(
					bidTrace.BuilderPubkey,
					bidTrace.Slot,
					payloadID(bidTrace.BlockHash.String(), bidTrace.Slot, bidTrace.ProposerPubkey.String()),
				); err != nil {
					log.Error(err, "failed to upsert block builder delivered payload")
				}

				if err := s.evtSender.SendBlockUnblindedEvent(
					payload.Slot(),
					gethcommon.Hash(res.BlockHash()),
					bidTrace.Value.BigInt(),
				); err != nil {
					log.Error(err, "failed to send block unblinded event to event bus")
				}
			}
		}()

		log.Info("received a block", "block", payload.BlockNumber(), "numTransactions", res.NumTx())
		httpJSONResponse(w, http.StatusOK, res)
	}
}

// @Tags Builder
// @Summary Validators scheduled to propose current and next epoch
// @Accept json
// @Produce json
// @Success 200 {object} []BuilderGetValidatorsResponseEntry
// @Router /relay/v1/builder/validators [get]
func (s *relay) perEpochValidatorsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := s.dutyState.All()
		httpJSONResponse(w, http.StatusOK, res)
	}
}

// @Tags Builder
// @Summary Submit new block
// @Accept json
// @Produce json
// @Param body body buildercapella.SubmitBlockRequest true "BuilderSubmitBlockRequest"
// @Success 200
// @Failure 400 {object} JSONError
// @Failure 501 {object} JSONError
// @Router /relay/v1/builder/blocks [post]
func (s *relay) submitNewBlockHandler(limiter *rateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		receivedAt := time.Now().UTC()
		allowCancellations := r.URL.Query().Get("cancellations") == "1"

		log := logger.WithValues(
			"method", "submitNewBlock",
			"userAgent", r.UserAgent(),
			"receivedAt", receivedAt,
			"allowCancellations", allowCancellations,
		)

		hReceivedAt := r.Header.Get("X-Req-Received-At")
		if hReceivedAt != "" {
			milli, err := strconv.ParseInt(hReceivedAt, 10, 64)
			if err == nil {
				receivedAt = time.UnixMilli(milli).UTC()
			} else {
				log.Error(err, "failed to parse received at header")
			}
		} else {
			log.Info("received at header not found")
		}

		log = log.WithValues("receivedAt", receivedAt)

		if allowCancellations && !s.allowBuilderCancellations {
			log.Error(errors.New("cancellations not allowed"), "cancellations not allowed")
			httpJSONError(w, http.StatusBadRequest, "cancellations not allowed")
			return
		}

		payload := new(BuilderSubmitBlockRequest)
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			log.Error(err, "failed to decode payload")
			httpJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}
		defer r.Body.Close() // nolint:errcheck

		if payload.IsEmpty() {
			log.Error(errors.New("payload incomplete"), "payload incomplete, missing message or execution payload")
			httpJSONError(w, http.StatusBadRequest, "payload incomplete")
			return
		}

		payloadBidTrace := payload.Message()

		_, span := s.tracer.Start(
			r.Context(),
			"submitNewBlock",
			trace.WithAttributes(
				attribute.Int64("slot", int64(payloadBidTrace.Slot)),
				attribute.String("blockHash", payloadBidTrace.BlockHash.String()),
				attribute.String("builderPubkey", payloadBidTrace.BuilderPubkey.String()),
				attribute.String("proposerPubkey", payloadBidTrace.ProposerPubkey.String()),
				attribute.String("parentHash", payloadBidTrace.ParentHash.String()),
			),
		)
		defer span.End()

		log = log.WithValues(
			"slot", payloadBidTrace.Slot,
			"builderPubkey", payloadBidTrace.BuilderPubkey,
			"blockHash", payloadBidTrace.BlockHash,
		)

		// reject submissions of builders that are unknown to us for the time being
		accepted, err := s.store.AreNewBlockBuildersAccepted()
		if err != nil {
			log.Error(err, "failed to check if new block builders are accepted")
		} else if !accepted {
			known, err := s.store.IsKnownBlockBuilder(payloadBidTrace.BuilderPubkey)
			if !known || err != nil {
				log.Error(err, "pausing submission of unknown block builder", "builderPubkey", payloadBidTrace.BuilderPubkey)
				httpJSONError(w, http.StatusBadRequest, "pausing submission of unknown block builders")
				return
			}
		}

		rlKey := fmt.Sprintf("%s_%d", payloadBidTrace.BuilderPubkey.String(), payloadBidTrace.Slot)

		if err := limiter.Wait(r.Context(), rlKey); err != nil {
			defer limiter.Close(rlKey)
			log.Error(errors.New("rate limit exceeded"), "no empty slots", "slot", payloadBidTrace.Slot, "builderPubkey", payloadBidTrace.BuilderPubkey)
			httpJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		defer limiter.Close(rlKey)

		headSlot := s.headSlot.Load()
		if payloadBidTrace.Slot <= headSlot {
			log.Error(errors.New("slot is older"), "payloads slot is too old", "headSlot", headSlot, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusBadRequest, "slot is too old")
			return
		}
		if payloadBidTrace.Slot > headSlot+1 {
			log.Error(errors.New("slot is too far ahead"), "payloads slot is too far ahead", "headSlot", headSlot, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusBadRequest, "slot is too far ahead")
			return
		}

		etime := s.genesisTime + payloadBidTrace.Slot*SecondsPerSlot
		if etime != payload.Timestamp() {
			log.Error(errors.New("invalid timestamp"), "payload genesis time has an invalid timestamp", "expectedTime", etime, "timestamp", payload.Timestamp())
			httpJSONError(w, http.StatusBadRequest, "invalid timestamp")
			return
		}

		slotDuty := s.dutyState.BySlot(payloadBidTrace.Slot)
		if slotDuty == nil {
			log.Error(errors.New("nil slot duty"), "no proposed slot duty found")
			httpJSONError(w, http.StatusBadRequest, "no slot duty")
			return
		}
		if slotDuty.Entry.Message.FeeRecipient != payloadBidTrace.ProposerFeeRecipient {
			log.Error(errors.New("fee recipient mismatch"), "slot duty and proposer fee recipient mismatch", "expected", slotDuty.Entry.Message.FeeRecipient, "actual", payloadBidTrace.ProposerFeeRecipient)
			httpJSONError(w, http.StatusBadRequest, "fee recipient mismatch")
			return
		}

		builder, err := s.store.BlockBuilder(payloadBidTrace.BuilderPubkey)
		if err != nil {
			log.Error(err, "failed to get block builder status")
		}

		if builder != nil && builder.Blacklisted {
			log.Info("builder is blacklisted")
			w.WriteHeader(http.StatusOK)
			return
		}

		log = log.WithValues(
			"proposerPubKey", payloadBidTrace.ProposerPubkey,
			"parentHash", payloadBidTrace.ParentHash,
			"value", payload.Value(),
			"tx", payload.NumTx(),
		)

		if payloadBidTrace.Value.Cmp(&ZeroU256) == 0 || payload.NumTx() == 0 {
			log.Info("payload has no transactions or its value is zero", "value", payloadBidTrace.Value)
			w.WriteHeader(http.StatusOK)
			return
		}

		if payloadBidTrace.BlockHash != payload.ExecutionPayloadBlockHash() || payloadBidTrace.ParentHash != payload.ExecutionPayloadParentHash() {
			log.Error(errors.New("block hash mismatch"), "block hash and parenthash mismatch", "blockHash", payloadBidTrace.BlockHash, "parentHash", payloadBidTrace.ParentHash, "payloadBlockHash", payload.ExecutionPayloadBlockHash(), "payloadParentHash", payload.ExecutionPayloadParentHash())
			httpJSONError(w, http.StatusBadRequest, "block hash and parenthash mismatch")
			return
		}

		s.randaoState.mux.RLock()
		randao := s.randaoState.expectedPrevRandao
		s.randaoState.mux.RUnlock()
		if payloadBidTrace.Slot != randao.slot {
			log.Error(errors.New("slot mismatch"), "prev randao is not updated yet", "randaoSlot", randao.slot, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusInternalServerError, "prev randao is not updated yet")
			return
		}
		if payload.ExecutionPayloadRandom().String() != randao.prevRandao {
			log.Error(errors.New("randao mismatch"), "execution randao mismatch", "expectedPrevRandao", randao.prevRandao, "actualExecutionRandom", payload.ExecutionPayloadRandom())
			httpJSONError(w, http.StatusBadRequest, "randao mismatch")
			return
		}

		withdrawals := payload.Withdrawals()
		if withdrawals != nil {
			s.withdrawalsState.mux.RLock()
			expectedRoot := s.withdrawalsState.expectedRoot
			s.withdrawalsState.mux.RUnlock()
			if expectedRoot.slot != payloadBidTrace.Slot {
				log.Info("unknown withdrawals at the moment")
				httpJSONError(w, http.StatusInternalServerError, "withdrawals are not known yet")
				return
			}
			root, err := computeWithdrawalsRoot(withdrawals)
			if err != nil {
				log.Error(err, "could not compute withdrawals root from payload")
				httpJSONError(w, http.StatusBadRequest, "could not compute withdrawals root")
				return
			}
			if expectedRoot.root != root {
				log.Info("incorrect withdrawals root", "got", root, "expected", expectedRoot.root)
				httpJSONError(w, http.StatusBadRequest, "incorrect withdrawals root")
				return
			}
		}

		sig := payload.Signature()
		ok, err := types.VerifySignature(payloadBidTrace, s.cfg.DomainBuilder, payloadBidTrace.BuilderPubkey[:], sig[:])
		if !ok || err != nil {
			log.Error(err, "invalid signature", "ok", ok)
			httpJSONError(w, http.StatusBadRequest, "invalid signature")
			return
		}

		latestSlot, err := s.store.LatestDeliveredSlotStats()
		if err != nil {
			log.Error(err, "latest slot stats not found")
		} else if payloadBidTrace.Slot <= latestSlot {
			log.Error(errors.New("payload slot too old"), "payload already delivered, slot is too old", "latestSlot", latestSlot, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusBadRequest, "payload already delivered")
			return
		}

		var ip string
		if s.traceIP {
			ip = userIP(r)
		}
		var simErr error
		defer func() {
			bidTraceExtended := BidTraceExtended{
				ExecutionPayloadKey: fmt.Sprintf("%d_%s_%s", payloadBidTrace.Slot, payloadBidTrace.ProposerPubkey.String(), payloadBidTrace.BlockHash.String()),
				Timestamp:           receivedAt,
				Signature:           sig,
				BidTrace: BidTrace{
					BlockNumber: payload.BlockNumber(),
					NumTx:       uint64(payload.NumTx()),
					BidTrace: types.BidTrace{
						Slot:                 payloadBidTrace.Slot,
						BlockHash:            payload.ExecutionPayloadBlockHash(),
						ParentHash:           payload.ExecutionPayloadParentHash(),
						BuilderPubkey:        payloadBidTrace.BuilderPubkey,
						ProposerPubkey:       payloadBidTrace.ProposerPubkey,
						ProposerFeeRecipient: payloadBidTrace.ProposerFeeRecipient,
						GasUsed:              payloadBidTrace.GasUsed,
						GasLimit:             payloadBidTrace.GasLimit,
						Value:                payloadBidTrace.Value,
					},
				},
				IP: ip,
			}

			if simErr != nil {
				bidTraceExtended.SimError = simErr.Error()
			}

			if err := s.store.PutBuilderBlockSubmissionsPayload(bidTraceExtended); err != nil {
				log.Error(err, "failed to store submission payload")
			}

			if err := s.store.UpsertBlockBuilderSubmissionPayload(
				bidTraceExtended.BuilderPubkey,
				bidTraceExtended.Slot,
				payloadID(bidTraceExtended.BlockHash.String(), bidTraceExtended.Slot, bidTraceExtended.ProposerPubkey.String()),
				simErr,
			); err != nil {
				log.Error(err, "failed to upsert block builder")
			}
		}()

		bestBid, err := s.store.BestBid(payloadBidTrace.Slot, payloadBidTrace.ParentHash, payloadBidTrace.ProposerPubkey)
		if err != nil {
			log.Error(err, "failed to get best bid")
		} else {
			log = log.WithValues("bestBid", bestBid.Value(), "submittedBid", payloadBidTrace.Value)

			if !allowCancellations && bestBid != nil && payload.Value().Cmp(bestBid.Value()) < 1 {
				simErr = errors.New("rejected bid because it is not better than the current best bid")
				log.Info("bid is not better than the current best bid")
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		if err := simulateBlockSubmission(r.Context(), &BuilderBlockValidationRequest{
			BuilderSubmitBlockRequest: *payload,
			RegisteredGasLimit:        slotDuty.Entry.Message.GasLimit,
		}, s.cfg.BlockSimURL); err != nil {
			simErr = err
			log.Error(err, "failed to simulate block submission", "uri", s.cfg.BlockSimURLSafe, "timeDiff", time.Since(receivedAt))
			httpJSONError(w, http.StatusBadRequest, "failed to simulate block submission")

			if errSend := s.evtSender.SendBlockSimulationFailedEvent(
				payloadBidTrace.Slot,
				payloadBidTrace.BuilderPubkey.String(),
				gethcommon.Hash(payloadBidTrace.BlockHash),
				payloadBidTrace.Value.BigInt(),
				err,
			); errSend != nil {
				log.Error(errSend, "failed to send block simulation failed event to event bus")
			}
			return
		}

		log = log.WithValues("simDuration", time.Since(receivedAt))

		log.Info("builder block submission simulated successfully")

		if allowCancellations {
			latestBuilderBid, err := s.store.LatestBuilderBid(payloadBidTrace.Slot, payloadBidTrace.ParentHash, payloadBidTrace.ProposerPubkey, payloadBidTrace.BuilderPubkey)
			if err != nil {
				log.Error(err, "failed to get latest builder bid")
			} else if latestBuilderBid != nil && uint64(receivedAt.UnixMilli()) < uint64(latestBuilderBid.Timestamp.UnixMilli()) {
				log.Error(errors.New("bid too old"), "bid is not the latest", "latest", latestBuilderBid.Timestamp.UnixMilli(), "received", receivedAt.UnixMilli())
				httpJSONError(w, http.StatusBadRequest, "bid is not the latest")
				return
			}
		}

		getHeaderResponse, err := buildGetHeaderResponse(payload, s.cfg.SecretKey, s.cfg.PublicKey, s.cfg.DomainBuilder)
		if err != nil {
			log.Error(err, "failed to build get header response")
			httpJSONError(w, http.StatusBadRequest, "failed to build get header response")
			return
		}
		builderBidHeaderResponse := BuilderBidHeaderResponse{
			Capella:   getHeaderResponse.Capella,
			Timestamp: receivedAt,
		}

		getPayloadResponse, err := buildGetPayloadResponse(payload)
		if err != nil {
			log.Error(err, "failed to build get payload response")
			httpJSONError(w, http.StatusBadRequest, "failed to build get payload response")
			return
		}
		versionedExecutedPayload := VersionedExecutedPayload{
			Capella:   getPayloadResponse.Capella,
			Timestamp: receivedAt,
		}

		bidTrace := BidTraceTimestamp{
			BidTrace: BidTrace{
				BidTrace:    *payloadBidTrace,
				BlockNumber: payload.BlockNumber(),
				NumTx:       uint64(payload.NumTx()),
			},
			Timestamp: receivedAt,
		}

		if err := s.store.PutBidTrace(bidTrace); err != nil {
			log.Error(err, "failed to save delivered payload")
			httpJSONError(w, http.StatusInternalServerError, "failed to save payload")
			return
		}

		if err := s.store.PutExecutedPayload(payloadBidTrace.Slot, payloadBidTrace.ProposerPubkey, payloadBidTrace.BlockHash, versionedExecutedPayload); err != nil {
			log.Error(err, "failed to save execution payload")
			httpJSONError(w, http.StatusInternalServerError, "failed to save execution payload")
			return
		}

		if err := s.store.PutLatestBuilderBid(payloadBidTrace.Slot, payloadBidTrace.ParentHash, payloadBidTrace.ProposerPubkey, payloadBidTrace.BuilderPubkey, builderBidHeaderResponse); err != nil {
			log.Error(err, "failed to save latest builder bid")
			httpJSONError(w, http.StatusInternalServerError, "failed to save latest builder bid")
			return
		}

		if err := s.store.UpdateBestBid(payloadBidTrace.Slot, payloadBidTrace.ParentHash, payloadBidTrace.ProposerPubkey); err != nil {
			log.Error(err, "failed to update best bid")
			httpJSONError(w, http.StatusInternalServerError, "failed to update best bid")
			return
		}

		log.Info("blocks received from builder")

		w.WriteHeader(http.StatusOK)

		if err := s.evtSender.SendBlockSubmittedEvent(
			payloadBidTrace.Slot,
			payloadBidTrace.BuilderPubkey.String(),
			gethcommon.Hash(payloadBidTrace.BlockHash),
			payloadBidTrace.Value.BigInt(),
		); err != nil {
			log.Error(err, "failed to send block submitted event to event bus")
		}
	}
}

// @Tags Data
// @Summary Proposer payload delivered
// @Description Proposer payload delivered
// @Accept  json
// @Produce  json
// @Param slot query string true "slot"
// @Param cursor query string true "cursor"
// @Param proposerPubkey query string true "proposerPubkey"
// @Param blockHash query string true "blockHash"
// @Param builderPubkey query string true "builderPubkey"
// @Params limit query string true "limit"
// @Success 200 {object} []BidTrace
// @Failure 400 {object} JSONError
// @Failure 500 {object} JSONError
// @Router /relay/v1/data/bidtraces/proposer_payload_delivered [get]
func (s *relay) deliveredPayloadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, span := s.tracer.Start(r.Context(), "proposerPayloadDelivered", trace.WithAttributes(attribute.String("query", r.URL.RawQuery)))
		defer span.End()

		log := logger.WithValues(
			"method", "proposerPayloadDelivered",
			"userAgent", r.UserAgent(),
			"query", r.URL.RawQuery,
		)

		query := newProposerPayloadQuery()

		slotStr := r.URL.Query().Get("slot")
		if slotStr != "" {
			slot, err := strconv.ParseUint(slotStr, 10, 64)
			if err != nil {
				log.Error(err, "invalid slot")
				httpJSONError(w, http.StatusBadRequest, "invalid slot")
				return
			}
			query.Slot = slot
		}

		cursorStr := r.URL.Query().Get("cursor")
		if cursorStr != "" {
			cursor, err := strconv.ParseUint(cursorStr, 10, 64)
			if err != nil {
				log.Error(err, "invalid cursor")
				httpJSONError(w, http.StatusBadRequest, "invalid cursor")
				return
			}
			query.Cursor = cursor
		}

		blockHashStr := r.URL.Query().Get("block_hash")
		if blockHashStr != "" {
			var blockHash types.Hash
			if err := blockHash.UnmarshalText([]byte(blockHashStr)); err != nil {
				log.Error(err, "invalid block hash")
				httpJSONError(w, http.StatusBadRequest, "invalid block hash")
				return
			}
			query.BlockHash = blockHash
		}

		blockNumberStr := r.URL.Query().Get("block_number")
		if blockNumberStr != "" {
			blockNumber, err := strconv.ParseUint(blockNumberStr, 10, 64)
			if err != nil {
				log.Error(err, "invalid block number")
				httpJSONError(w, http.StatusBadRequest, "invalid block number")
				return
			}
			query.BlockNumber = blockNumber
		}

		proposerPubkey := r.URL.Query().Get("proposer_pubkey")
		if proposerPubkey != "" {
			var pbKey types.PublicKey
			if err := pbKey.UnmarshalText([]byte(proposerPubkey)); err != nil {
				log.Error(err, "invalid proposer pubkey")
				httpJSONError(w, http.StatusBadRequest, "invalid proposer pubkey")
				return
			}
			query.ProposerPubkey = pbKey
		}

		limitStr := r.URL.Query().Get("limit")
		if limitStr != "" {
			limit, err := strconv.ParseUint(limitStr, 10, 64)
			if err != nil {
				log.Error(err, "invalid limit")
				httpJSONError(w, http.StatusBadRequest, "invalid limit")
				return
			}
			query.Limit = limit
		}

		orderByStr := r.URL.Query().Get("order_by")
		if orderByStr != "" {
			if orderByStr == "value" {
				query.OrderBy = 1
			} else if orderByStr == "-value" {
				query.OrderBy = -1
			}
		}

		ok, err := query.IsValid()
		if !ok || err != nil {
			log.Error(err, "invalid query", "ok", ok)
			httpJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		delivered, err := s.store.DeliveredPayloads(query)
		if err != nil {
			log.Error(err, "failed to get payload delivered")
			httpJSONError(w, http.StatusInternalServerError, "failed to get payload delivered")
			return
		}

		res := make([]BidTrace, len(delivered))
		for i, d := range delivered {
			res[i] = d.BidTrace
		}

		log.Info("get payload delivered", "count", len(delivered))
		httpJSONResponse(w, http.StatusOK, res)
	}
}

// @Tags Data
// @Summary Builder blocks received
// @Description Builder blocks received
// @Accept  json
// @Produce  json
// @Param slot query string true "slot"
// @Param blockHash query string true "blockHash"
// @Param blockNumber query string true "blockNumber"
// @Param limit query string true "limit"
// @Success 200 {object} []BidTraceReceived
// @Failure 400 {object} JSONError
// @Failure 500 {object} JSONError
// @Router /relay/v1/data/bidtraces/builder_blocks_received [get]
func (s *relay) submissionPayloadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, span := s.tracer.Start(r.Context(), "builderBlocksReceived", trace.WithAttributes(attribute.String("query", r.URL.RawQuery)))
		defer span.End()

		log := logger.WithValues(
			"method", "builderBlocksReceived",
			"userAgent", r.UserAgent(),
			"query", r.URL.RawQuery,
		)

		query := newBuilderBlockQuery()

		slotStr := r.URL.Query().Get("slot")
		if slotStr != "" {
			slot, err := strconv.ParseUint(slotStr, 10, 64)
			if err != nil {
				log.Error(err, "invalid slot")
				httpJSONError(w, http.StatusBadRequest, "invalid slot")
				return
			}
			query.Slot = slot
		}

		blockHashStr := r.URL.Query().Get("block_hash")
		if blockHashStr != "" {
			var blockHash types.Hash
			if err := blockHash.UnmarshalText([]byte(blockHashStr)); err != nil {
				log.Error(err, "invalid block hash")
				httpJSONError(w, http.StatusBadRequest, "invalid block hash")
				return
			}
			query.BlockHash = blockHash
		}

		blockNumberStr := r.URL.Query().Get("block_number")
		if blockNumberStr != "" {
			blockNumber, err := strconv.ParseUint(blockNumberStr, 10, 64)
			if err != nil {
				log.Error(err, "invalid block number")
				httpJSONError(w, http.StatusBadRequest, "invalid block number")
				return
			}
			query.BlockNumber = blockNumber
		}

		limitStr := r.URL.Query().Get("limit")
		if limitStr != "" {
			limit, err := strconv.ParseUint(limitStr, 10, 64)
			if err != nil {
				log.Error(err, "invalid limit")
				httpJSONError(w, http.StatusBadRequest, "invalid limit")
				return
			}
			query.Limit = limit
		}

		if !query.isValid() {
			log.Error(errors.New("invalid query"), "URL query is invalid")
			httpJSONError(w, http.StatusBadRequest, "invalid query")
			return
		}

		submissions, err := s.store.BlockSubmissionsPayload(query)
		if err != nil {
			log.Error(err, "failed to get builder blocks")
			httpJSONError(w, http.StatusInternalServerError, "failed to get builder blocks")
			return
		}
		log.Info("get builder blocks", "count", len(submissions))
		httpJSONResponse(w, http.StatusOK, submissions)
	}
}

// @Tags Data
// @Summary Registered validator
// @Description Registered validator
// @Accept  json
// @Produce  json
// @Param pubkey query string true "pubkey"
// @Success 200 {object} types.SignedValidatorRegistration
// @Failure 400 {object} JSONError
// @Failure 500 {object} JSONError
// @Router /relay/v1/data/validator_registration [get]
func (s *relay) registeredValidatorHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, span := s.tracer.Start(r.Context(), "getRegisteredValidator", trace.WithAttributes(attribute.String("query", r.URL.RawQuery)))
		defer span.End()

		log := logger.WithValues(
			"method", "getRegisteredValidator",
			"userAgent", r.UserAgent(),
			"query", r.URL.RawQuery,
		)

		pubKeyStr := r.URL.Query().Get("pubkey")
		if pubKeyStr == "" {
			log.Error(errors.New("pubkey missing"), "pubkey is required")
			httpJSONError(w, http.StatusBadRequest, "pubkey is required")
			return
		}

		var pubKey types.PublicKey
		if err := pubKey.UnmarshalText([]byte(pubKeyStr)); err != nil {
			log.Error(err, "invalid pubkey")
			httpJSONError(w, http.StatusBadRequest, "invalid pubkey")
			return
		}

		validator, err := s.store.RegisteredValidator(pubKey)
		if err != nil {
			log.Error(err, "failed to get validator")
			httpJSONError(w, http.StatusBadRequest, "failed to get validator")
			return
		}
		log.Info("got validator", "pubkey", pubKeyStr)
		httpJSONResponse(w, http.StatusOK, validator)
	}
}

func buildGetHeaderResponse(payload *BuilderSubmitBlockRequest, sk *bls.SecretKey, pubkey *types.PublicKey, domain types.Domain) (*GetHeaderResponse, error) {
	if payload.Capella != nil {
		sig, err := builderSubmitBlockReqToSignedBuilderBidCapella(payload.Capella, sk, (*phase0.BLSPubKey)(pubkey), domain)
		if err != nil {
			return nil, err
		}
		return &GetHeaderResponse{
			Capella: &builderspec.VersionedSignedBuilderBid{
				Capella: sig,
				Version: consensusspec.DataVersionCapella,
			},
		}, nil
	}

	return nil, ErrPayloadNil
}

func builderSubmitBlockReqToSignedBuilderBidCapella(req *buildercapella.SubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain types.Domain) (*buildercapella.SignedBuilderBid, error) {
	if req == nil {
		return nil, ErrReqNil
	}

	if sk == nil {
		return nil, ErrSecretKeyNil
	}

	header, err := capellaPayloadToPayloadHeader(req.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	builderBid := buildercapella.BuilderBid{
		Value:  req.Message.Value,
		Header: header,
		Pubkey: *pubkey,
	}

	sig, err := types.SignMessage(&builderBid, domain, sk)
	if err != nil {
		return nil, err
	}

	return &buildercapella.SignedBuilderBid{
		Message:   &builderBid,
		Signature: phase0.BLSSignature(sig),
	}, nil
}

func capellaPayloadToPayloadHeader(payload *consensuscapella.ExecutionPayload) (*consensuscapella.ExecutionPayloadHeader, error) {
	if payload == nil {
		return nil, ErrPayloadNil
	}

	txs := utilbellatrix.ExecutionPayloadTransactions{Transactions: payload.Transactions}
	txsRoot, err := txs.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	withdrawals := utilcapella.ExecutionPayloadWithdrawals{Withdrawals: payload.Withdrawals}
	withdrawalsRoot, err := withdrawals.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return &consensuscapella.ExecutionPayloadHeader{
		ParentHash:       payload.ParentHash,
		FeeRecipient:     payload.FeeRecipient,
		StateRoot:        payload.StateRoot,
		ReceiptsRoot:     payload.ReceiptsRoot,
		LogsBloom:        payload.LogsBloom,
		PrevRandao:       payload.PrevRandao,
		BlockNumber:      payload.BlockNumber,
		GasLimit:         payload.GasLimit,
		GasUsed:          payload.GasUsed,
		Timestamp:        payload.Timestamp,
		ExtraData:        payload.ExtraData,
		BaseFeePerGas:    payload.BaseFeePerGas,
		BlockHash:        payload.BlockHash,
		TransactionsRoot: txsRoot,
		WithdrawalsRoot:  withdrawalsRoot,
	}, nil
}

func buildGetPayloadResponse(payload *BuilderSubmitBlockRequest) (*GetPayloadResponse, error) {
	if payload.Capella != nil {
		return &GetPayloadResponse{
			Capella: &builderapi.VersionedExecutionPayload{
				Version: consensusspec.DataVersionCapella,
				Capella: payload.Capella.ExecutionPayload,
			},
		}, nil
	}

	return nil, ErrPayloadNil
}

func unblindedSignedBeaconBlock(b *SignedBlindedBeaconBlock, payload *GetPayloadResponse) *SignedBeaconBlock {
	if b.Capella != nil {
		return &SignedBeaconBlock{Capella: &consensuscapella.SignedBeaconBlock{
			Signature: b.Capella.Signature,
			Message: &consensuscapella.BeaconBlock{
				Slot:          b.Capella.Message.Slot,
				ProposerIndex: b.Capella.Message.ProposerIndex,
				ParentRoot:    b.Capella.Message.ParentRoot,
				StateRoot:     b.Capella.Message.StateRoot,
				Body: &consensuscapella.BeaconBlockBody{
					BLSToExecutionChanges: b.Capella.Message.Body.BLSToExecutionChanges,
					RANDAOReveal:          b.Capella.Message.Body.RANDAOReveal,
					ETH1Data:              b.Capella.Message.Body.ETH1Data,
					Graffiti:              b.Capella.Message.Body.Graffiti,
					ProposerSlashings:     b.Capella.Message.Body.ProposerSlashings,
					AttesterSlashings:     b.Capella.Message.Body.AttesterSlashings,
					Attestations:          b.Capella.Message.Body.Attestations,
					Deposits:              b.Capella.Message.Body.Deposits,
					VoluntaryExits:        b.Capella.Message.Body.VoluntaryExits,
					SyncAggregate:         b.Capella.Message.Body.SyncAggregate,
					ExecutionPayload:      payload.Capella.Capella,
				},
			},
		}}
	}

	return nil
}

func userIP(r *http.Request) string {
	a := r.Header.Get("X-Forwarded-For")
	if a == "" {
		a = r.RemoteAddr
	}
	return strings.Split(a, ",")[0]
}

func payloadID(blockHash string, slot uint64, proposerPubkey string) string {
	return fmt.Sprintf("%s/%d_%s", blockHash, slot, proposerPubkey)
}

type randaoHelper struct {
	slot       uint64
	prevRandao string
}

type randaoState struct {
	expectedPrevRandao *randaoHelper
	mux                sync.RWMutex
}

func newRandaoState() *randaoState {
	return &randaoState{
		expectedPrevRandao: &randaoHelper{},
	}
}

type withdrawalsHelper struct {
	slot uint64
	root phase0.Root
}

type withdrawalsState struct {
	expectedRoot *withdrawalsHelper
	mux          sync.RWMutex
}

func newWithdrawalsState() *withdrawalsState {
	return &withdrawalsState{
		expectedRoot: &withdrawalsHelper{},
	}
}

func computeWithdrawalsRoot(w []*consensuscapella.Withdrawal) (phase0.Root, error) {
	withdrawals := utilcapella.ExecutionPayloadWithdrawals{Withdrawals: w}
	return withdrawals.HashTreeRoot()
}

func compareExecutionHeaderPayload(block *SignedBlindedBeaconBlock, payload *GetPayloadResponse) error {
	if block.Capella != nil {
		if payload.Capella == nil {
			return ErrMismatchPayloads
		}
		header, err := capellaPayloadToPayloadHeader(payload.Capella.Capella)
		if err != nil {
			return err
		}

		blockTreeRoot, err := block.Capella.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}
		headerTreeRoot, err := header.HashTreeRoot()
		if err != nil {
			return err
		}
		if blockTreeRoot != headerTreeRoot {
			return ErrMismatchHeaders
		}

		return nil
	}

	return ErrNoPayloads
}
