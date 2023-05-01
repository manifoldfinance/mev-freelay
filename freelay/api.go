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
	"archive/tar"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/params"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/julienschmidt/httprouter"
	"github.com/manifoldfinance/mev-freelay/logger"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type API interface {
	HTTPServer(addr string) *http.Server
}

type api struct {
	store            StoreSetter
	knownValidators  KnownValidatorGetter
	activeValidators ActiveValidatorGetter
	genesisTime      uint64
	dbPrefix         string
	currDBPrefix     string
	network          string
	tracer           trace.Tracer
}

func NewAPI(store StoreSetter, known KnownValidatorGetter, active ActiveValidatorGetter, genesis uint64, network string, dbPrefix, currDBPrefix string, tracer trace.Tracer) *api {
	a := api{
		store:            store,
		knownValidators:  known,
		activeValidators: active,
		genesisTime:      genesis,
		dbPrefix:         dbPrefix,
		currDBPrefix:     currDBPrefix,
		network:          network,
		tracer:           tracer,
	}

	return &a
}

func (a *api) HTTPServer(addr string) *http.Server {
	mux := a.routes()

	srv := http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return &srv
}

func (a *api) routes() *httprouter.Router {
	mux := httprouter.New()
	p := message.NewPrinter(language.English)

	mux.HandlerFunc(http.MethodGet, "/stats", wrapper(a.statsHandler(p)))
	mux.HandlerFunc(http.MethodGet, "/builders", wrapper(a.buildersHandler()))
	mux.HandlerFunc(http.MethodGet, "/archive", wrapper(a.archiveHandler()))
	mux.HandlerFunc(http.MethodDelete, "/prune/:slot", wrapper(a.pruneHandler()))
	mux.HandlerFunc(http.MethodGet, "/backup", wrapper(a.backupHandler()))

	mux.HandlerFunc(http.MethodPost, "/internal/v1/builder/:pubkey", wrapper(a.internalBuilderHandler()))
	mux.HandlerFunc(http.MethodPost, "/internal/v1/block_builders/reject", wrapper(a.internalRejectBlockBuildersHandler()))
	mux.HandlerFunc(http.MethodPost, "/internal/v1/block_builders/accept", wrapper(a.internalAcceptBlockBuildersHandler()))

	mux.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	return mux
}

type statsResponse struct {
	TotalValidators        string            `json:"total_validators"`
	RegisteredValidators   string            `json:"registered_validators"`
	ActiveValidators       string            `json:"active_validators"`
	LatestSlot             string            `json:"latest_slot"`
	TotalDeliveredPayloads string            `json:"total_delivered_payloads"`
	Network                string            `json:"network"`
	DeliveredPayload       []prettyDelivered `json:"delivered_payload"`
}

func (a *api) statsHandler(prt *message.Printer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, span := a.tracer.Start(r.Context(), "statsHandler")
		defer span.End()

		log := logger.WithValues("service", "webAPI", "method", "statsHandler")

		latestSlot, err := a.store.LatestSlotStats()
		if err != nil {
			log.Error(err, "failed getting latest slot")
			http.Error(w, "failed getting latest slot", http.StatusInternalServerError)
			return
		}

		registered, err := a.store.AllRegisteredValidators()
		if err != nil {
			log.Error(err, "failed getting registered validators")
			http.Error(w, "failed getting registered validators", http.StatusInternalServerError)
			return
		}

		deliveredCount, err := a.store.DeliveredPayloadsCount()
		if err != nil {
			log.Error(err, "failed getting delivered payloads")
			http.Error(w, "failed getting delivered payloads", http.StatusInternalServerError)
			return
		}

		query := ProposerPayloadQuery{
			Limit:  100,
			Cursor: latestSlot,
		}

		orderByStr := r.URL.Query().Get("order_by")
		if orderByStr != "" {
			if orderByStr == "value" {
				query.OrderBy = 1
			} else if orderByStr == "-value" {
				query.OrderBy = -1
			}
		}

		delivered, err := a.store.DeliveredPayloads(query)
		if err != nil {
			log.Error(err, "failed getting delivered payloads")
			http.Error(w, "failed getting delivered payloads", http.StatusInternalServerError)
			return
		}

		prettyDelivered := prettifyDelivered(delivered, prt)

		stats := statsResponse{
			TotalValidators:        prt.Sprintf("%d", a.knownValidators.Count()),
			RegisteredValidators:   prt.Sprintf("%d", len(registered)),
			ActiveValidators:       prt.Sprintf("%d", len(a.activeValidators.Get())),
			LatestSlot:             prt.Sprintf("%d", latestSlot),
			TotalDeliveredPayloads: prt.Sprintf("%d", deliveredCount),
			Network:                a.network,
			DeliveredPayload:       prettyDelivered,
		}
		httpJSONResponse(w, http.StatusOK, stats)
	}
}

func (a *api) buildersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues("service", "webAPI", "method", "buildersHandler")

		builders, err := a.store.AllBlockBuilders()
		if err != nil {
			log.Error(err, "failed getting builders")
			http.Error(w, "failed getting builders", http.StatusInternalServerError)
			return
		}

		res := buildersResponse{
			Builders:         prettifyBuilders(builders),
			NumTotalBuilders: uint64(len(builders)),
			NumBuilders:      uint64(len(builders)),
		}

		httpJSONResponse(w, http.StatusOK, res)
	}
}

func (a *api) archiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues(
			"service", "webAPI",
			"method", "archiveHandler",
			"genesisTime", a.genesisTime,
			"path", r.URL.Path,
		)

		slot := uint64((uint64(time.Now().UTC().Add(-6*time.Hour).Unix()) - a.genesisTime) / 12)
		log = log.WithValues("slot", slot)

		bw := bufio.NewWriter(w)
		defer bw.Flush() // nolint:errcheck
		tw := tar.NewWriter(bw)
		defer tw.Close() // nolint:errcheck

		if err := Archive(a.store.DB(), tw, w, slot); err != nil {
			if err == ErrNoArchivePayloadsFound {
				log.Info("no payloads to archive")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			log.Error(err, "failed archiving payloads")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info("archived payloads")
	}
}

func (a *api) pruneHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues("service", "webAPI", "method", "pruneHandler")

		params := httprouter.ParamsFromContext(r.Context())
		slotStr := params.ByName("slot")
		if slotStr == "" {
			log.Error(errors.New("invalid path"), "url path is invalid", "path", r.URL.Path)
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}

		slot, err := strconv.ParseUint(slotStr, 10, 64)
		if err != nil {
			log.Error(err, "failed parsing toSlot", "toSlot", slotStr)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Info("pruning payloads", "toSlot", slot)
		if err := Prune(a.store.DB(), slot); err != nil {
			log.Error(err, "failed pruning payloads")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info("successfully pruned payloads")
		w.WriteHeader(http.StatusOK)
	}
}

func (a *api) backupHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues("service", "webAPI", "method", "backupHandler")
		bw := bufio.NewWriter(w)
		defer bw.Flush() // nolint:errcheck

		tw := tar.NewWriter(bw)
		defer tw.Close() // nolint:errcheck
		log.Info("creating backups")
		err := CreateBackup(w, tw, a.store.DB(), a.dbPrefix, a.currDBPrefix)
		if err != nil {
			log.Error(err, "failed backing up db")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info("successfully backed up db")
	}
}

func (a *api) internalBuilderHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues(
			"method", "internalBuilderHandler",
			"httpMethod", r.Method,
			"userAgent", r.UserAgent(),
			"query", r.URL.RawQuery,
		)

		params := httprouter.ParamsFromContext(r.Context())
		pubKeyStr := params.ByName("pubkey")
		if pubKeyStr == "" {
			log.Error(errors.New("invalid pubkey"), "pubkey is empty")
			http.Error(w, "pubkey is a required field", http.StatusBadRequest)
			return
		}

		var pubKey types.PublicKey
		if err := pubKey.UnmarshalText([]byte(pubKeyStr)); err != nil {
			log.Error(err, "invalid pubkey")
			http.Error(w, "invalid pubkey", http.StatusBadRequest)
			return
		}

		var payload blockBuilderReqBody
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			log.Error(err, "failed to decode request body")
			http.Error(w, "failed to decode request body", http.StatusBadRequest)
			return
		}

		highPriority := payload.HighPriority
		blacklisted := payload.Blacklisted
		if err := a.store.SetBlockBuilderStatus(pubKey, highPriority, blacklisted); err != nil {
			log.Error(err, "failed to set builder", "pubkey", pubKeyStr, "highPriority", highPriority, "blacklisted", blacklisted)
			http.Error(w, "failed to set builder", http.StatusInternalServerError)
			return
		}

		log.Info("set builder", "pubkey", pubKeyStr, "highPriority", highPriority, "blacklisted", blacklisted)
		httpJSONResponse(w, http.StatusOK, blockBuilderStatus{
			NewStatus: getBlockBuilderStatus(highPriority, blacklisted),
		})
	}
}

func (a *api) internalRejectBlockBuildersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues(
			"method", "internalRejectBlockBuildersHandler",
			"httpMethod", r.Method,
			"userAgent", r.UserAgent(),
		)

		if err := a.store.RejectNewBlockBuilders(); err != nil {
			log.Error(err, "failed to enable reject new block builders")
			http.Error(w, "failed to enable reject new block builders", http.StatusInternalServerError)
			return
		}

		log.Info("rejecting new block builders")
		w.WriteHeader(http.StatusOK)
	}
}

func (a *api) internalAcceptBlockBuildersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.WithValues(
			"method", "internalAcceptBlockBuildersHandler",
			"httpMethod", r.Method,
			"userAgent", r.UserAgent(),
		)

		if err := a.store.AcceptNewBlockBuilders(); err != nil {
			log.Error(err, "failed to enable accepting new block builders")
			http.Error(w, "failed to enable accepting new block builders", http.StatusInternalServerError)
			return
		}

		log.Info("accepting new block builders")
		w.WriteHeader(http.StatusOK)
	}
}

type prettyDelivered struct {
	BlockNumber uint64     `json:"block_number,string"`
	NumTx       string     `json:"num_tx"`
	BlockHash   types.Hash `json:"block_hash" ssz-size:"32"`
	Slot        uint64     `json:"slot,string"`
	Epoch       uint64     `json:"epoch,string"`
	Value       string     `json:"value"`
	Timestamp   string     `json:"timestamp"`
	TimestampMs int64      `json:"timestamp_ms,string"`
}

func prettifyDelivered(bidTrace []BidTraceReceived, prt *message.Printer) []prettyDelivered {
	pretty := make([]prettyDelivered, 0)
	for _, b := range bidTrace {
		p := new(prettyDelivered)
		p.BlockHash = b.BlockHash
		p.Slot = b.Slot
		p.BlockNumber = b.BlockNumber
		p.Value = weiToEther(b.Value.BigInt()).String()
		p.Epoch = uint64(b.Slot / SlotsPerEpoch)
		p.NumTx = prt.Sprintf("%d", b.NumTx)
		p.Timestamp = prt.Sprintf("%s", time.UnixMilli(b.TimestampMs).UTC().Format(time.RFC1123))
		p.TimestampMs = b.TimestampMs
		pretty = append(pretty, *p)
	}
	return pretty
}

type buildersResponse struct {
	Builders         []prettyBuilder `json:"builders"`
	NumTotalBuilders uint64          `json:"num_total_builders"`
	NumBuilders      uint64          `json:"num_builders"`
}

type prettyBuilder struct {
	BlockBuilder
	CreatedAtStr            string `json:"created_at_str"`
	UpdatedAtStr            string `json:"updated_at_str"`
	HighPriorityStr         string `json:"high_priority_str"`
	BlacklistedStr          string `json:"blacklisted_str"`
	FinalDeliveredAtStr     string `json:"final_delivered_at_str"`
	FinalSubmissionAtStr    string `json:"final_submission_at_str"`
	FirstDeliveredAtStr     string `json:"first_delivered_at_str"`
	FirstSubmissionAtStr    string `json:"first_submission_at_str"`
	ShowDescription         bool   `json:"show_description"`
	InitialDeliveredSlot    string `json:"initial_delivered_slot"`
	InitialSubmissionSlot   string `json:"initial_submission_slot"`
	FinalDeliveredSlot      string `json:"final_delivered_slot"`
	FinalSubmissionSlot     string `json:"final_submission_slot"`
	ShowDeliveredLink       bool   `json:"show_delivered_link"`
	ShowFinalDeliveredLink  bool   `json:"show_final_delivered_link"`
	ShowFinalSubmissionLink bool   `json:"show_final_submission_link"`
	ShowSubmissionLink      bool   `json:"show_submission_link"`
	ShowFinalSubmissionAt   bool   `json:"show_final_submission_at"`
	ShowFinalDeliveredAt    bool   `json:"show_final_delivered_at"`
}

func prettifyBuilders(b []BlockBuilder) []prettyBuilder {
	pretty := make([]prettyBuilder, 0)
	for _, builder := range b {
		p := new(prettyBuilder)
		p.BlockBuilder = builder

		p.ShowDescription = builder.Description != ""
		p.CreatedAtStr = builder.CreatedAt.Format(time.RFC1123)
		p.UpdatedAtStr = builder.UpdatedAt.Format(time.RFC1123)
		p.FinalDeliveredAtStr = builder.LastDeliveredAt.Format(time.RFC1123)
		p.FinalSubmissionAtStr = builder.LastSubmissionAt.Format(time.RFC1123)
		p.FirstDeliveredAtStr = builder.FirstDeliveredAt.Format(time.RFC1123)
		p.FirstSubmissionAtStr = builder.FirstSubmissionAt.Format(time.RFC1123)
		if builder.Blacklisted {
			p.BlacklistedStr = "Yes"
		} else {
			p.BlacklistedStr = "No"
		}

		if builder.HighPriority {
			p.HighPriorityStr = "Yes"
		} else {
			p.HighPriorityStr = "No"
		}

		if builder.FirstDeliveredSlot == 0 {
			p.InitialDeliveredSlot = "N/A"
			p.ShowDeliveredLink = false
		} else {
			p.InitialDeliveredSlot = fmt.Sprintf("%d", builder.FirstDeliveredSlot)
			p.ShowDeliveredLink = true
		}

		if builder.LastDeliveredSlot == 0 {
			p.FinalDeliveredSlot = "N/A"
			p.ShowFinalDeliveredLink = false
		} else {
			p.FinalDeliveredSlot = fmt.Sprintf("%d", builder.LastDeliveredSlot)
			p.ShowFinalDeliveredLink = true
		}

		if builder.FirstSubmissionSlot == 0 {
			p.InitialSubmissionSlot = "N/A"
			p.ShowSubmissionLink = false
		} else {
			p.InitialSubmissionSlot = fmt.Sprintf("%d", builder.FirstSubmissionSlot)
			p.ShowSubmissionLink = true
		}

		if builder.LastSubmissionSlot == 0 {
			p.FinalSubmissionSlot = "N/A"
			p.ShowFinalSubmissionLink = false
		} else {
			p.FinalSubmissionSlot = fmt.Sprintf("%d", builder.LastSubmissionSlot)
			p.ShowFinalSubmissionLink = true
		}

		if builder.LastSubmissionAt.IsZero() {
			p.ShowFinalSubmissionAt = false
		} else {
			p.ShowFinalSubmissionAt = true
		}

		if builder.LastDeliveredAt.IsZero() {
			p.ShowFinalDeliveredAt = false
		} else {
			p.ShowFinalDeliveredAt = true
		}

		pretty = append(pretty, *p)
	}
	return pretty
}

func weiToEther(wei *big.Int) *big.Float {
	f := new(big.Float)
	f.SetPrec(236)
	f.SetMode(big.ToNearestEven)
	fWei := new(big.Float)
	fWei.SetPrec(236)
	fWei.SetMode(big.ToNearestEven)
	return f.Quo(fWei.SetInt(wei), big.NewFloat(params.Ether))
}

type blockBuilderStatus struct {
	NewStatus string `json:"new_status"`
}

func getBlockBuilderStatus(isHighPriority bool, isBlacklisted bool) string {
	if isBlacklisted {
		return "blacklisted"
	}

	if isHighPriority {
		return "high_priority"
	}

	return "low_priority"
}

type blockBuilderReqBody struct {
	Blacklisted  bool `json:"blacklisted"`
	HighPriority bool `json:"high_priority"`
}
