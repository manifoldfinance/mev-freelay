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
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/cockroachdb/pebble"
	"github.com/gorilla/mux"

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
	"github.com/manifoldfinance/mev-freelay/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/atomic"
	"golang.org/x/exp/slices"
)

const (
	SlotsPerEpoch          = 32
	SecondsPerSlot         = 12
	DurationPerSlot        = time.Second * SecondsPerSlot
	DurationPerEpoch       = DurationPerSlot * time.Duration(SlotsPerEpoch)
	registeredValidatorTTL = 30 // seconds
)

var (
	ignoreGetHeaderHeaders = []string{"mev-boost/v1.5.0 Go-http-client/1.1"}
)

type Relay interface {
	HTTPServer(addr string, readTimeout, readHeadTimeout, writeTimeout, idleTimeout, maxHeaderBytes uint64) *http.Server
	Stop()
}

type relay struct {
	ctx            context.Context
	log            logger.Logger
	store          StoreSetter
	beacon         MultiBeacon
	knownValidator KnownValidatorSetter
	dutyState      DutySetter
	cfg            *RelayConfig
	evtSender      EventSender
	genesisTime    uint64
	maxRateLimit   uint64
	tracer         trace.Tracer
	traceIP        bool

	beaconProposeTimeout        time.Duration
	cutOffTimeoutHeader         uint64
	cutOffTimeoutPayload        uint64
	maxSubmitBlockBodySizeBytes uint64
	getPayloadRetryMax          uint64
	getPayloadRetryMS           uint64

	headSlot               atomic.Uint64
	isUpdatingPropDuties   atomic.Bool
	isRefreshingValidators atomic.Bool
	isStopping             atomic.Bool
	unblindInFlight        sync.WaitGroup

	randaoState                 *randaoState
	withdrawalsState            *withdrawalsState
	latestDeliveredPayloadState *latestDeliveredPayloadState

	builderBlockSimulator BuilderBlockSimulator

	validatorCh chan SignedValidatorRegistrationExtended
}

func NewRelay(
	ctx context.Context,
	store StoreSetter,
	beacon MultiBeacon,
	builderBlockSimulator BuilderBlockSimulator,
	known KnownValidatorSetter,
	duty DutySetter,
	evtSender EventSender,
	cfg *RelayConfig,
	genesis, headSlot uint64,
	maxChQueue, maxRateLimit, beaconProposeTimeout, cutOffTimeoutHeader, cutOffTimeoutPayload, maxSubmitBlockBodySizeBytes, getPayloadRetryMax, getPayloadRetryMS uint64,
	traceIP bool,
	tracer trace.Tracer,
) (*relay, error) {
	log := logger.WithValues("module", "relay")

	// get latest delivered payload and set it to the latest delivered payload state
	deliveredPayload, err := store.Delivered(ProposerPayloadQuery{
		Limit: 1,
	})
	if err != nil {
		log.Error(err, "failed to get latest delivered payload")
	}
	latestDeliveredState := newLatestDeliveredPayloadState()
	if len(deliveredPayload) > 0 {
		latestDeliveredState.Set(deliveredPayload[0].Slot, deliveredPayload[0].BlockHash)
	}

	r := &relay{
		ctx:            ctx,
		log:            log,
		store:          store,
		beacon:         beacon,
		knownValidator: known,
		dutyState:      duty,
		cfg:            cfg,
		evtSender:      evtSender,
		genesisTime:    genesis,
		maxRateLimit:   maxRateLimit,
		tracer:         tracer,
		traceIP:        traceIP,

		beaconProposeTimeout:        time.Duration(beaconProposeTimeout) * time.Millisecond,
		cutOffTimeoutHeader:         cutOffTimeoutHeader,
		cutOffTimeoutPayload:        cutOffTimeoutPayload,
		getPayloadRetryMax:          getPayloadRetryMax,
		getPayloadRetryMS:           getPayloadRetryMS,
		maxSubmitBlockBodySizeBytes: maxSubmitBlockBodySizeBytes,

		randaoState:                 newRandaoState(),
		withdrawalsState:            newWithdrawalsState(),
		latestDeliveredPayloadState: latestDeliveredState,
		builderBlockSimulator:       builderBlockSimulator,

		validatorCh: make(chan SignedValidatorRegistrationExtended, maxChQueue),
	}

	log.Info("processing current slot", "headSlot", headSlot)
	if err := r.processNewSlot(headSlot); err != nil {
		log.Error(err, "failed to process current slot", "headSlot", headSlot)
	}

	log.Info("start loop processing of new slots")
	go r.startLoopProcessNewSlot()

	log.Info("start loop to process new payload attributes")
	go r.startLoopProcessPayloadAttributes()

	log.Info("start parallel validator registration")
	go r.startValidatorRegistration()

	return r, nil
}

func (s *relay) HTTPServer(addr string, readTimeout, readHeadTimeout, writeTimeout, idleTimeout, maxHeaderBytes uint64) *http.Server {
	mux := http.NewServeMux()
	r := s.routes()

	wrapped := wrapper(r)
	rgzip := gziphandler.GzipHandler(wrapped)

	mux.Handle("/", rgzip)

	srv := http.Server{
		Addr:    addr,
		Handler: mux,

		ReadTimeout:       time.Duration(readTimeout) * time.Millisecond,
		ReadHeaderTimeout: time.Duration(readHeadTimeout) * time.Millisecond,
		WriteTimeout:      time.Duration(writeTimeout) * time.Second,
		IdleTimeout:       time.Duration(idleTimeout) * time.Second,
		MaxHeaderBytes:    int(maxHeaderBytes),
	}

	return &srv
}

func (s *relay) Stop() {
	if s.isStopping.Swap(true) {
		return // already stopping
	}

	log := s.log.WithValues("method", "Stop")

	log.Info("waiting for unblind in flight")
	s.unblindInFlight.Wait()

	log.Info("ready to be stopped")
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
func (s *relay) routes() *mux.Router {
	router := mux.NewRouter()

	// root
	router.HandleFunc("/", s.rootHandler()).Methods(http.MethodGet)

	// proposer endpoints
	router.HandleFunc("/eth/v1/builder/status", s.statusHandler()).Methods(http.MethodGet)
	router.HandleFunc("/eth/v1/builder/validators", s.registerValidatorHandler()).Methods(http.MethodPost)
	router.HandleFunc("/eth/v1/builder/header/{slot:[0-9]+}/{parentHash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}", s.builderHeaderHandler()).Methods(http.MethodGet)
	router.HandleFunc("/eth/v1/builder/blinded_blocks", s.unblindBlindedBlockHandler()).Methods(http.MethodPost)

	// builder endpoints
	router.HandleFunc("/relay/v1/builder/validators", s.perEpochValidatorsHandler()).Methods(http.MethodGet)
	router.HandleFunc("/relay/v1/builder/blocks", s.submitNewBlockHandler(NewRateLimiter(s.maxRateLimit, DurationPerEpoch))).Methods(http.MethodPost) // X requests per key

	// data endpoints
	router.HandleFunc("/relay/v1/data/bidtraces/proposer_payload_delivered", s.deliveredPayloadHandler()).Methods(http.MethodGet)
	router.HandleFunc("/relay/v1/data/bidtraces/builder_blocks_received", s.submissionPayloadHandler()).Methods(http.MethodGet)
	router.HandleFunc("/relay/v1/data/validator_registration", s.registeredValidatorHandler()).Methods(http.MethodGet)

	router.Use(mux.CORSMethodMiddleware(router))

	return router
}

func (s *relay) startLoopProcessNewSlot() {
	evt := make(chan HeadEvent)

	log := s.log.WithValues("method", "startLoopProcessNewSlot")

	log.Info("subscribing to head events")
	s.beacon.SubscribeToHeadEvents(evt)

	for s.ctx.Err() == nil {
		select {
		case <-s.ctx.Done():
			return
		case e := <-evt:
			log.Info("received new head event", "headSlot", e.Slot)
			if err := s.processNewSlot(e.Slot); err != nil {
				log.Error(err, "failed to process new slot", "headSlot", e.Slot)
			}
		}
	}
}

func (s *relay) startLoopProcessPayloadAttributes() {
	evt := make(chan PayloadAttributesEvent)

	log := s.log.WithValues("method", "startLoopProcessPayloadAttributes")

	log.Info("subscribing to payload attributes events")
	s.beacon.SubscribeToPayloadAttributesEvents(evt)

	for s.ctx.Err() == nil {
		select {
		case <-s.ctx.Done():
			return
		case e := <-evt:
			log.Info("received new payload attributes event")
			if err := s.processPayloadAttributes(e); err != nil {
				log.Error(err, "failed to process payload attributes")
			}
		}
	}
}

func (s *relay) startValidatorRegistration() {
	log := s.log.WithValues("method", "startValidatorRegistration")

	for v := range s.validatorCh {
		if s.ctx.Err() != nil {
			return
		}

		ok, err := types.VerifySignature(v.Message, s.cfg.DomainBuilder, v.Message.Pubkey[:], v.Signature[:])
		if err != nil {
			log.Error(err, "could not verify signature", "msg", v.Message, "signature", v.Signature, "pubkey", v.Message.Pubkey)
			continue
		} else if !ok {
			log.Error(errors.New("invalid signature"), "invalid signature", "msg", v.Message, "signature", v.Signature, "pubkey", v.Message.Pubkey)
			continue
		}

		if err := s.store.PutValidator(v.Message.Pubkey, v); err != nil {
			log.Error(err, "failed to put validator", "pubkey", v.Message.Pubkey)
		}
	}
}

func (s *relay) updateProposerDuties(headSlot uint64) error {
	if s.isUpdatingPropDuties.Swap(true) {
		return nil
	}
	defer s.isUpdatingPropDuties.Store(false)

	epochFrom := headSlot / uint64(SlotsPerEpoch)
	epochTo := epochFrom + 1

	log := s.log.WithValues(
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
		validator, err := s.store.Validator(*pubkey)
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
	prevHeadSlot := s.headSlot.Load()
	log := s.log.WithValues(
		"method", "processNewSlot",
		"headSlot", headSlot,
		"prevHeadSlot", prevHeadSlot,
		"receivedAt", time.Now().UTC(),
	)

	log.Info("processing new slot")

	if headSlot <= prevHeadSlot {
		return fmt.Errorf("slot %d is older than current head slot %d", headSlot, prevHeadSlot)
	}

	if prevHeadSlot > 0 {
		for i := prevHeadSlot + 1; i < headSlot; i++ {
			log.Info("missed slot", "slot", i, "prevHeadSlot", prevHeadSlot, "headSlot", headSlot)
		}
	}

	s.headSlot.Store(headSlot)

	go func() {
		log.Info("updating proposer duties")
		if err := s.updateProposerDuties(headSlot); err != nil {
			log.Error(err, "failed to update proposer duties")
		}
	}()

	diffSlot := headSlot - s.knownValidator.LastSlot()
	if diffSlot >= 6 {
		go func() {
			log.Info("refreshing known validators", "diffSlot", diffSlot)
			if err := s.refreshKnownValidators(); err != nil {
				log.Error(err, "failed to refresh known validators")
			}
		}()
	}

	go func() {
		log.Info("updating latest slot")
		if err := s.store.SetLatestSlot(headSlot); err != nil {
			log.Error(err, "failed to update latest slot")
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

	parentBlockHash := e.Data.ParentBlockHash
	log := s.log.WithValues(
		"method", "processPayloadAttributes",
		"proposalSlot", proposalSlot,
		"headSlot", headSlot,
		"parentBlockHash", parentBlockHash,
	)

	currRandao := s.randaoState.ByHash(parentBlockHash)
	currWithdrawals := s.withdrawalsState.ByHash(parentBlockHash)
	if currRandao != nil && currWithdrawals != nil {
		log.Info("skipping payload attributes", "parentBlockHash", parentBlockHash)
		return nil
	}

	withdrawals := e.Data.PayloadAttributes.Withdrawals
	root, err := computeWithdrawalsRoot(withdrawals)
	if err != nil {
		log.Error(err, "failed to compute withdrawals root")
		return err
	}

	s.randaoState.Cleanup(headSlot)
	s.withdrawalsState.Cleanup(headSlot)
	log.Info("cleaned up old randao and withdrawals")

	prevRandao := e.Data.PayloadAttributes.PrevRandao
	s.randaoState.Put(parentBlockHash, &randaoHelper{
		slot:       proposalSlot,
		prevRandao: prevRandao,
	})
	log.Info("updated expected randao", "prevRandao", prevRandao)

	s.withdrawalsState.Put(parentBlockHash, &withdrawalsHelper{
		slot: proposalSlot,
		root: root,
	})
	log.Info("updated expected withdrawals", "root", root)

	return nil
}

func (s *relay) refreshKnownValidators() error {
	if s.isRefreshingValidators.Swap(true) {
		return nil
	}
	defer s.isRefreshingValidators.Store(false)

	headSlot := s.headSlot.Load()

	log := s.log.WithValues(
		"method", "refreshKnownValidators",
		"headSlot", headSlot,
	)

	log.Info("fetching validators")
	ftime := time.Now().UTC()
	validators, err := s.beacon.Validators(headSlot)
	if err != nil {
		return err
	}
	log.Info("fetched validators", "fetchValidatorsDur", time.Since(ftime))

	vHexs := make(map[types.PubkeyHex]uint64)
	vByIndx := make(map[uint64]types.PubkeyHex)
	for _, v := range validators.Data {
		pk := types.NewPubkeyHex(v.Validator.Pubkey)
		vHexs[pk] = v.Index
		vByIndx[v.Index] = pk
	}

	s.knownValidator.Set(vHexs, vByIndx, headSlot)
	log.Info("set known validators")
	s.knownValidator.Updated(true)

	return nil
}

func (s *relay) rootHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpResponse(w, http.StatusOK, "MEV Freelay API")
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
		receivedAt := time.Now().UTC()
		log := s.log.WithValues(
			"method", "registerValidator",
			"userAgent", r.UserAgent(),
			"headSlot", s.headSlot.Load(),
			"receivedAt", receivedAt,
		)

		if !s.knownValidator.IsUpdated() {
			log.Error(errors.New("known validators are not updated"), "known validators are not updated")
			httpJSONError(w, http.StatusInternalServerError, "known validators are not yet available")
			return
		}

		_, span := s.tracer.Start(r.Context(), "registerValidator", trace.WithAttributes(attribute.Int("contentLength", int(r.ContentLength))))
		defer span.End()

		regTimestamp := uint64(time.Now().UTC().Unix() + 10)

		if r.ContentLength == 0 {
			log.Error(errors.New("empty request body"), "request body is empty")
			httpJSONError(w, http.StatusBadRequest, "request body is empty")
			return
		}

		p := make([]types.SignedValidatorRegistration, 0)
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			log.Error(err, "failed to decode request body")
			httpJSONError(w, http.StatusBadRequest, "failed to decode request body")
			return
		}

		total := len(p)

		var ip string
		if s.traceIP {
			ip = userIP(r)
		}

		var (
			numProcessedRegistrations uint64
			errProcessedRegs          error
		)

		for _, v := range p {
			pvp := time.Now().UTC()
			t := v.Message.Timestamp
			if t < s.genesisTime {
				log.Info("timestamp is too far in the past", "pubkey", v.Message.Pubkey, "timestamp", t, "genesisTime", s.genesisTime)
				errProcessedRegs = ErrValidatorTimestampTooFarInThePast
				break
			} else if t > regTimestamp {
				log.Info("timestamp is too far in the future", "pubkey", v.Message.Pubkey, "timestamp", t, "regTimestamp", regTimestamp)
				errProcessedRegs = ErrValidatorTimestampTooFarInTheFuture
				break
			}

			ok := s.knownValidator.IsKnown(v.Message.Pubkey.PubkeyHex())
			if !ok {
				log.Info("unknown validator", "pubkey", v.Message.Pubkey)
				errProcessedRegs = ErrValidatorUnknown
				break
			}

			prevValidator, err := s.store.ValidatorExtended(v.Message.Pubkey)
			if err != nil {
				log.Error(err, "failed to get validator", "pubkey", v.Message.Pubkey, "dur", time.Since(pvp))
			} else if prevValidator.Message.Timestamp >= t {
				continue
			} else if prevValidator.Timestamp.Unix()+registeredValidatorTTL > time.Now().UTC().Unix() && prevValidator.Message.FeeRecipient == v.Message.FeeRecipient && prevValidator.Message.GasLimit == v.Message.GasLimit {
				continue
			}

			validatorExtended := SignedValidatorRegistrationExtended{
				SignedValidatorRegistration: v,
				IP:                          ip,
				Timestamp:                   time.Now().UTC(),
			}

			numProcessedRegistrations++

			select {
			case s.validatorCh <- validatorExtended:
			default:
				log.Error(ErrValidatorChanRegsFull, "failed to put validators on channel")
			}
		}

		if errProcessedRegs != nil {
			log.Error(errProcessedRegs, "failed to process registrations", "total", total, "processed", numProcessedRegistrations)
			httpJSONError(w, http.StatusBadRequest, errProcessedRegs.Error())
			return
		}

		log.Info("successful registration", "total", total)
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
		headSlot := s.headSlot.Load()
		log := s.log.WithValues(
			"method", "getHeader",
			"userAgent", ua,
			"path", r.URL.Path,
			"headSlot", headSlot,
			"receivedAt", receivedAt,
		)

		_, span := s.tracer.Start(r.Context(), "getHeader", trace.WithAttributes(attribute.String("pth", r.URL.Path)))
		defer span.End()

		params := mux.Vars(r)
		slotStr := params["slot"]
		parentHash := params["parentHash"]
		pubkey := params["pubkey"]

		slot, err := strconv.ParseUint(slotStr, 10, 64)
		if err != nil {
			log.Error(err, "urls slot is invalid", "slot", slotStr)
			httpJSONError(w, http.StatusBadRequest, "invalid slot")
			return
		}

		if len(parentHash) != 66 {
			log.Error(err, "invalid parent hash", "parentHash", parentHash)
			httpJSONError(w, http.StatusBadRequest, "invalid parent hash")
			return
		}

		if len(pubkey) != 98 {
			log.Error(err, "invalid pubkey", "pubkey", pubkey)
			httpJSONError(w, http.StatusBadRequest, "invalid pubkey")
			return
		}

		if slot < headSlot {
			log.Error(errors.New("slot is too old"), "provided slot is too old", "slot", slot, "headSlot", headSlot)
			httpJSONError(w, http.StatusBadRequest, "slot is too old")
			return
		}

		if slices.Contains(ignoreGetHeaderHeaders, ua) {
			log.Info("ignoring mev-boost/v1.5.0")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		slotStart := (s.genesisTime + slot*SecondsPerSlot) * 1000
		timeIntoSlot := receivedAt.UnixMilli() - int64(slotStart)
		if s.cutOffTimeoutHeader > 0 && timeIntoSlot > int64(s.cutOffTimeoutHeader) {
			log.Info("too late to get header", "timeIntoSlot", timeIntoSlot, "cutOffTimeout", s.cutOffTimeoutHeader)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		bid, err := s.store.BestBid(slot, parentHash, pubkey)
		if err != nil && err != pebble.ErrNotFound {
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
		s.unblindInFlight.Add(1)
		defer s.unblindInFlight.Done()
		receivedAt := time.Now().UTC()

		log := s.log.WithValues(
			"method", "getPayload",
			"userAgent", r.UserAgent(),
			"headSlot", s.headSlot.Load(),
			"receivedAt", receivedAt,
		)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error(err, "failed to read body")
			httpJSONError(w, http.StatusBadRequest, "failed to read body")
			return
		}

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
			"proposerIndex", payload.ProposerIndex(),
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

		log = log.WithValues("pubkey", pubKey)

		var (
			exErr  error
			res    *GetPayloadResponse
			ticker = time.NewTicker(time.Duration(s.getPayloadRetryMS) * time.Millisecond)
		)
		for i := 0; i < int(s.getPayloadRetryMax); i++ {
			res, exErr = s.store.Executed(payload.Slot(), pubKey, payload.BlockHash())
			if exErr == nil {
				break
			}
			log.Info("retrying to get executed payload because sometimes we get fetching for executed data even before it is written in the DB", "retry", i, "timeout", s.getPayloadRetryMS)
			// retry getPayloadRetryMax times with X delay in getPayloadRetryMax-1 attempts because sometimes we get fetching for executed data even before it is written in the DB
			<-ticker.C
		}
		ticker.Stop()

		if exErr != nil {
			log.Error(exErr, "failed to get executed payload")
			httpJSONError(w, http.StatusBadRequest, "failed to get executed payload")
			return
		}

		log.Info("found executed payload", "slot", payload.Slot(), "blockHash", payload.BlockHash())

		lastSlot, lastHash := s.latestDeliveredPayloadState.Get()
		if payload.Slot() < lastSlot {
			log.Error(errors.New("slot was already delivered"), "slot", payload.Slot(), "lastSlot", lastSlot)
			httpJSONError(w, http.StatusBadRequest, "slot was already delivered")
			return
		} else if payload.Slot() == lastSlot && lastHash != nil && payload.BlockHash() != *lastHash {
			log.Error(errors.New("payload already delivered for slot with a different block hash"), "blockHash", payload.BlockHash(), "lastHash", lastHash)
			httpJSONError(w, http.StatusBadRequest, "payload already delivered for slot with a different hash")
			return
		}

		s.latestDeliveredPayloadState.Set(payload.Slot(), payload.BlockHash())

		var (
			errMissed, errDelivered error
			bidTrace                *BidTrace
			ip                      string
		)

		if s.traceIP {
			ip = userIP(r)
		}

		slotStart := (s.genesisTime + payload.Slot()*SecondsPerSlot) * 1000
		timeIntoSlot := receivedAt.UnixMilli() - int64(slotStart)

		log = log.WithValues("timeIntoSlot", timeIntoSlot, "cutOffTimeout", s.cutOffTimeoutPayload, "slotStart", slotStart)

		defer func() {
			log.Info("upserting unblinded block", "errDelivered", errDelivered, "errMissed", errMissed)

			if errDelivered == nil {
				if err := s.store.PutDelivered(DeliveredPayload{
					BidTrace:                 *bidTrace,
					SignedBlindedBeaconBlock: payload,
					Timestamp:                receivedAt,
					IP:                       ip,
				}); err != nil {
					log.Error(err, "failed to put unblind data")
					return
				}

				if err := s.store.UpsertBuilderDelivered(bidTrace.BuilderPubkey, bidTrace.Slot, payloadID(bidTrace.BlockHash.String(), bidTrace.Slot, bidTrace.ProposerPubkey.String())); err != nil {
					log.Error(err, "failed to upsert block builder delivered")
				}

				if err := s.evtSender.SendBlockUnblindedEvent(
					bidTrace.Slot,
					gethcommon.Hash(bidTrace.BlockHash),
					bidTrace.Value.BigInt(),
				); err != nil {
					log.Error(err, "failed to send block unblinded event to event bus")
				}
			} else if errMissed == nil {
				if err := s.store.PutMissed(MissedPayload{
					TimeIntoSlot:   timeIntoSlot,
					Timestamp:      receivedAt,
					SlotStart:      slotStart,
					Slot:           payload.Slot(),
					BlockHash:      payload.BlockHash(),
					ProposerPubkey: pubKey,
					IP:             ip,
					Error:          errMissed.Error(),
					DeliveredError: errDelivered.Error(),
				}); err != nil {
					log.Error(err, "failed to put missed data")
				}
			}
		}()

		if timeIntoSlot < 0 {
			earlyMS := time.Now().UTC().UnixMilli() - int64(slotStart)
			if earlyMS < 0 {
				delayMS := earlyMS * -1
				log = log.WithValues("delayMS", delayMS)
				log.Info("delaying unblinding block because it is too early")
				time.Sleep(time.Duration(delayMS) * time.Millisecond)
			}
		} else if s.cutOffTimeoutPayload > 0 && timeIntoSlot > int64(s.cutOffTimeoutPayload) {
			errMissed = ErrMissedBlock
			log.Error(ErrMissedBlock, "too late to unblind block")
			httpJSONError(w, http.StatusBadRequest, "too late to unblind block")
			return
		}

		if err := compareExecutionHeaderPayload(payload, res); err != nil {
			errDelivered = err
			log.Error(err, "failed to compare execution header and payload")
			httpJSONError(w, http.StatusBadRequest, "failed to compare execution header and payload")
			return
		}

		unblindedBlock := unblindedSignedBeaconBlock(payload, res)
		startTime := time.Now().UTC()

		log = log.WithValues("startTimePublishBlock", startTime)

		if err := s.beacon.PublishBlock(unblindedBlock); err != nil {
			errDelivered = err
			log.Error(err, "failed to publish block")
			httpJSONError(w, http.StatusBadRequest, "failed to publish block")
			return
		}

		log.Info("block published", "slot", payload.Slot(), "blockHash", payload.BlockHash(), "duration", time.Since(startTime).Milliseconds())

		// wait for the block to be propagate over other p2p nodes
		time.Sleep(s.beaconProposeTimeout)

		bt, err := s.store.BidTrace(payload.Slot(), pubKey, payload.BlockHash())
		if err != nil {
			errDelivered = err
			log.Error(err, "failed to get bid trace")
			httpJSONError(w, http.StatusBadRequest, "failed to get bid trace")
			return
		}
		bidTrace = bt
		log.Info("unblinded a block", "block", payload.BlockNumber(), "numTransactions", res.NumTx(), "bidTraceSlot", bidTrace.Slot, "bidTraceBlockHash", bidTrace.BlockHash, "bidTraceBuilderPubkey", bidTrace.BuilderPubkey, "bidTraceProposerPubkey", bidTrace.ProposerPubkey)

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
func (s *relay) submitNewBlockHandler(limiter RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		receivedAt := time.Now().UTC()
		allowCancellations := r.URL.Query().Get("cancellations") == "1"
		contentType := r.Header.Get("Content-Type")
		headSlot := s.headSlot.Load()

		log := s.log.WithValues(
			"method", "submitNewBlock",
			"userAgent", r.UserAgent(),
			"allowCancellations", allowCancellations,
			"contentType", contentType,
			"headSlot", headSlot,
			"receivedAt", receivedAt,
		)

		if allowCancellations {
			log.Error(errors.New("cancellations not allowed"), "cancellations not allowed")
			httpJSONError(w, http.StatusBadRequest, "cancellations not allowed")
			return
		}

		decodeT := time.Now().UTC()

		var (
			err    error
			reader io.Reader = r.Body
		)
		if r.Header.Get("Content-Encoding") == "gzip" {
			reader, err = gzip.NewReader(r.Body)
			if err != nil {
				log.Error(err, "failed to create gzip reader")
				httpJSONError(w, http.StatusBadRequest, "failed to create gzip reader")
				return
			}
		}

		body, err := io.ReadAll(io.LimitReader(reader, int64(s.maxSubmitBlockBodySizeBytes)))
		if err != nil {
			log.Error(err, "failed to read body")
			httpJSONError(w, http.StatusBadRequest, "failed to read body")
			return
		}

		payload := new(BuilderSubmitBlockRequest)
		if contentType == "application/octet-stream" {
			payload.Capella = new(buildercapella.SubmitBlockRequest)
			if err := payload.Capella.UnmarshalSSZ(body); err != nil {
				log.Error(err, "failed to unmarshal ssz payload")

				if err := json.Unmarshal(body, &payload); err != nil {
					log.Error(err, "failed to unmarshal json payload as well")
					httpJSONError(w, http.StatusBadRequest, "invalid body")
					return
				}

				log = log.WithValues("decoded", "json")
			} else {
				log = log.WithValues("decoded", "ssz")
			}
		} else if err := json.Unmarshal(body, &payload); err != nil {
			log.Error(err, "failed to unmarshal json payload")
			httpJSONError(w, http.StatusBadRequest, "invalid body")
			return
		} else {
			log = log.WithValues("decoded", "json")
		}

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
			"proposerPubKey", payloadBidTrace.ProposerPubkey,
			"parentHash", payloadBidTrace.ParentHash,
			"decodeDur", time.Since(decodeT),
		)

		rlKey := fmt.Sprintf("%s_%d", payloadBidTrace.BuilderPubkey.String(), payloadBidTrace.Slot)
		if err := limiter.Wait(r.Context(), rlKey); err != nil {
			defer limiter.Close(rlKey)
			log.Error(errors.New("rate limit exceeded"), "no empty slots", "slot", payloadBidTrace.Slot, "builderPubkey", payloadBidTrace.BuilderPubkey)
			httpJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		defer limiter.Close(rlKey)

		if payloadBidTrace.Slot <= headSlot {
			log.Error(errors.New("slot is older"), "payloads slot is too old", "headSlot", headSlot, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusBadRequest, "slot is too old")
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
		} else if !strings.EqualFold(slotDuty.Entry.Message.FeeRecipient.String(), payloadBidTrace.ProposerFeeRecipient.String()) {
			log.Error(errors.New("fee recipient mismatch"), "slot duty and proposer fee recipient mismatch", "expected", slotDuty.Entry.Message.FeeRecipient, "actual", payloadBidTrace.ProposerFeeRecipient)
			httpJSONError(w, http.StatusBadRequest, "fee recipient mismatch")
			return
		}

		builder, err := s.store.Builder(payloadBidTrace.BuilderPubkey)
		if err != nil {
			log.Error(err, "failed to get block builder status")
		}

		if builder != nil && builder.Blacklisted {
			log.Info("builder is blacklisted")
			w.WriteHeader(http.StatusOK)
			return
		}

		log = log.WithValues(
			"value", payload.Value(),
			"tx", payload.NumTx(),
		)

		if payloadBidTrace.Value.Cmp(&ZeroU256) == 0 || payload.NumTx() == 0 {
			log.Info("payload has no transactions or its value is zero", "value", payloadBidTrace.Value)
			w.WriteHeader(http.StatusOK)
			return
		}

		if payloadBidTrace.BlockHash != payload.ExecutionPayloadBlockHash() || payloadBidTrace.ParentHash != payload.ExecutionPayloadParentHash() {
			log.Error(errors.New("block hash mismatch"), "block hash and parent hash mismatch", "blockHash", payloadBidTrace.BlockHash, "parentHash", payloadBidTrace.ParentHash, "payloadBlockHash", payload.ExecutionPayloadBlockHash(), "payloadParentHash", payload.ExecutionPayloadParentHash())
			httpJSONError(w, http.StatusBadRequest, "block hash and parent hash mismatch")
			return
		}

		randao := s.randaoState.ByHash(payloadBidTrace.ParentHash.String())
		if randao == nil || payloadBidTrace.Slot != randao.slot {
			log.Error(errors.New("slot mismatch"), "payload attributes not updated yet", "randao", randao, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusInternalServerError, "payload attributes not updated yet")
			return
		}
		if payload.ExecutionPayloadRandom().String() != randao.prevRandao {
			log.Error(errors.New("randao mismatch"), "execution randao mismatch", "expectedPrevRandao", randao.prevRandao, "actualExecutionRandom", payload.ExecutionPayloadRandom())
			httpJSONError(w, http.StatusBadRequest, "randao mismatch")
			return
		}

		expectedRoot := s.withdrawalsState.ByHash(payloadBidTrace.ParentHash.String())
		if expectedRoot == nil || expectedRoot.slot != payloadBidTrace.Slot {
			log.Error(errors.New("slot mismatch"), "payload withdrawals not updated yet", "expectedRoot", expectedRoot, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusInternalServerError, "payload withdrawals not updated yet")
			return
		}
		root, err := computeWithdrawalsRoot(payload.Withdrawals())
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

		latestSlot, _ := s.latestDeliveredPayloadState.Get()
		if payloadBidTrace.Slot <= latestSlot {
			log.Error(errors.New("payload slot too old"), "payload already delivered, slot is too old", "latestSlot", latestSlot, "payloadSlot", payloadBidTrace.Slot)
			httpJSONError(w, http.StatusBadRequest, "payload already delivered")
			return
		}

		tsig := time.Now().UTC()
		sig := payload.Signature()
		ok, err := types.VerifySignature(payloadBidTrace, s.cfg.DomainBuilder, payloadBidTrace.BuilderPubkey[:], sig[:])
		if !ok || err != nil {
			log.Error(err, "invalid signature", "ok", ok)
			httpJSONError(w, http.StatusBadRequest, "invalid signature")
			return
		}

		log = log.WithValues("sigValidDur", time.Since(tsig))

		// if we got to here means the payload is valid and we can start processing it

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

			if err := s.store.PutSubmitted(bidTraceExtended); err != nil {
				log.Error(err, "failed to put submitted block")
				return
			}

			if err := s.store.UpsertBuilderSubmitted(bidTraceExtended.BuilderPubkey, bidTraceExtended.Slot, payloadID(bidTraceExtended.BlockHash.String(), bidTraceExtended.Slot, bidTraceExtended.ProposerPubkey.String()), simErr); err != nil {
				log.Error(err, "failed to upsert block builder submitted")
			}
		}()

		bestBid, err := s.store.BestBid(payloadBidTrace.Slot, payloadBidTrace.ParentHash.String(), payloadBidTrace.ProposerPubkey.String())
		if err != nil {
			log.Error(err, "failed to get best bid")
		} else {
			log = log.WithValues("bestBid", bestBid.Value(), "submittedBid", payloadBidTrace.Value)
			if bestBid != nil && payload.Value().Cmp(bestBid.Value()) < 1 {
				simErr = errors.New("accepted bid but it is not validated because it is not better than the current best bid")
				log.Info("accepted bid but it not validated because it is not better than the current best bid")
				httpResponse(w, http.StatusAccepted, "accepted bid but it not validated because it is not better than the current best bid")
				return
			}
		}

		tsim := time.Now().UTC()
		if err := s.builderBlockSimulator.SimulateBlockSubmission(r.Context(), &BuilderBlockValidationRequest{
			BuilderSubmitBlockRequest: *payload,
			RegisteredGasLimit:        slotDuty.Entry.Message.GasLimit,
		}); err != nil {
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

		log = log.WithValues("simDur", time.Since(tsim))

		log.Info("builder block submission simulated successfully")

		getHeaderResponse, err := buildGetHeaderResponse(payload, s.cfg.SecretKey, s.cfg.PublicKey, s.cfg.DomainBuilder)
		if err != nil {
			log.Error(err, "failed to build get header response")
			httpJSONError(w, http.StatusBadRequest, "failed to build get header response")
			return
		}

		getPayloadResponse, err := buildGetPayloadResponse(payload)
		if err != nil {
			log.Error(err, "failed to build get payload response")
			httpJSONError(w, http.StatusBadRequest, "failed to build get payload response")
			return
		}

		if err := s.store.PutBuilderBid(
			BidTrace{
				BidTrace:    *payloadBidTrace,
				BlockNumber: payload.BlockNumber(),
				NumTx:       uint64(payload.NumTx()),
			},
			*getPayloadResponse,
			*getHeaderResponse,
			receivedAt,
		); err != nil {
			log.Error(err, "failed to put submitted block")
			httpJSONError(w, http.StatusInternalServerError, "failed to put submitted block")
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

		receivedAt := time.Now().UTC()
		log := s.log.WithValues(
			"method", "proposerPayloadDelivered",
			"userAgent", r.UserAgent(),
			"query", r.URL.RawQuery,
			"receivedAt", receivedAt,
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

		delivered, err := s.store.Delivered(query)
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

		receivedAt := time.Now().UTC()
		log := s.log.WithValues(
			"method", "builderBlocksReceived",
			"userAgent", r.UserAgent(),
			"query", r.URL.RawQuery,
			"receivedAt", receivedAt,
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

		submissions, err := s.store.Submitted(query)
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

		receivedAt := time.Now().UTC()
		log := s.log.WithValues(
			"method", "getRegisteredValidator",
			"userAgent", r.UserAgent(),
			"query", r.URL.RawQuery,
			"receivedAt", receivedAt,
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

		validator, err := s.store.Validator(pubKey)
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
	expectedRandao map[string]*randaoHelper
	mux            sync.RWMutex
}

func newRandaoState() *randaoState {
	return &randaoState{
		expectedRandao: make(map[string]*randaoHelper),
	}
}

func (r *randaoState) Put(parentHash string, randao *randaoHelper) {
	r.mux.Lock()
	defer r.mux.Unlock()
	r.expectedRandao[parentHash] = randao
}

func (r *randaoState) ByHash(parentHash string) *randaoHelper {
	r.mux.RLock()
	defer r.mux.RUnlock()
	randao, ok := r.expectedRandao[parentHash]
	if !ok {
		return nil
	}
	return randao
}

func (r *randaoState) Cleanup(slot uint64) {
	r.mux.Lock()
	defer r.mux.Unlock()
	for k, v := range r.expectedRandao {
		if v.slot < slot {
			delete(r.expectedRandao, k)
		}
	}
}

type latestDeliveredPayloadState struct {
	mux       sync.RWMutex
	slot      uint64
	blockHash *types.Hash
}

func newLatestDeliveredPayloadState() *latestDeliveredPayloadState {
	return &latestDeliveredPayloadState{
		slot:      0,
		blockHash: nil,
	}
}

func (l *latestDeliveredPayloadState) Set(slot uint64, blockHash types.Hash) {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.slot = slot
	l.blockHash = &blockHash
}

func (l *latestDeliveredPayloadState) Get() (uint64, *types.Hash) {
	l.mux.RLock()
	defer l.mux.RUnlock()
	return l.slot, l.blockHash
}

type withdrawalsHelper struct {
	slot uint64
	root phase0.Root
}

type withdrawalsState struct {
	expectedRoot map[string]*withdrawalsHelper
	mux          sync.RWMutex
}

func newWithdrawalsState() *withdrawalsState {
	return &withdrawalsState{
		expectedRoot: make(map[string]*withdrawalsHelper),
	}
}

func (w *withdrawalsState) Put(parentHash string, withdrawals *withdrawalsHelper) {
	w.mux.Lock()
	defer w.mux.Unlock()
	w.expectedRoot[parentHash] = withdrawals
}

func (w *withdrawalsState) ByHash(parentHash string) *withdrawalsHelper {
	w.mux.RLock()
	defer w.mux.RUnlock()
	withdrawals, ok := w.expectedRoot[parentHash]
	if !ok {
		return nil
	}
	return withdrawals
}

func (w *withdrawalsState) Cleanup(slot uint64) {
	w.mux.Lock()
	defer w.mux.Unlock()
	for k, v := range w.expectedRoot {
		if v.slot < slot {
			delete(w.expectedRoot, k)
		}
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
