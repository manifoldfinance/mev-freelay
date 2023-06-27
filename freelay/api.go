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
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/params"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/manifoldfinance/mev-freelay/logger"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type API interface {
	Handler() map[string]any
}

type api struct {
	store           StoreSetter
	knownValidators KnownValidatorGetter
	genesisTime     uint64
	network         string
	publicKey       types.PublicKey
	tracer          trace.Tracer
	p               *message.Printer
}

func NewAPI(store StoreSetter, known KnownValidatorGetter, genesis uint64, network string, publickKey types.PublicKey, tracer trace.Tracer) *api {
	a := api{
		store:           store,
		knownValidators: known,
		genesisTime:     genesis,
		network:         network,
		publicKey:       publickKey,
		tracer:          tracer,
		p:               message.NewPrinter(language.English),
	}

	return &a
}

func (a *api) Handler() map[string]any {
	h := map[string]any{
		"envs": map[string]string{
			"network": a.network,
			"pubkey":  a.publicKey.String(),
		},
		"stats":                  a.stats,
		"builders":               a.builders,
		"archiveHandler":         a.archiveHandler,
		"backupHandler":          a.backupHandler,
		"pruneHandler":           a.pruneHandler,
		"internalBuilderHandler": a.internalBuilderHandler,
	}

	return h
}

type statsResponse struct {
	TotalValidators      string
	RegisteredValidators string
	ActiveValidators     string
	LatestSlot           string
	TotalDelivered       string
	Delivered            []prettyDelivered
}

func (a *api) stats(r *http.Request) statsResponse {
	_, span := a.tracer.Start(r.Context(), "statsHandler")
	defer span.End()

	log := logger.WithValues("service", "webAPI", "method", "statsHandler")

	_, spanv := a.tracer.Start(r.Context(), "statsGetValidators")
	registered, err := a.store.CountValidators()
	if err != nil {
		spanv.End()
		log.Error(err, "failed getting registered validators")
		return statsResponse{}
	}
	spanv.End()

	deliveredCount, err := a.store.DeliveredCount()
	if err != nil {
		log.Error(err, "failed getting delivered payloads")
		return statsResponse{}
	}

	latestSlot, err := a.store.LatestSlot()
	if err != nil {
		log.Error(err, "failed getting latest slot")
		return statsResponse{}
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

	delivered, err := a.store.Delivered(query)
	if err != nil {
		log.Error(err, "failed getting delivered payloads")
		return statsResponse{}
	}

	prettyDelivered := prettifyDelivered(delivered, a.p)

	stats := statsResponse{
		TotalValidators:      a.p.Sprintf("%d", a.knownValidators.Count()),
		RegisteredValidators: a.p.Sprintf("%d", registered),
		LatestSlot:           a.p.Sprintf("%d", latestSlot),
		TotalDelivered:       a.p.Sprintf("%d", deliveredCount),
		Delivered:            prettyDelivered,
	}
	return stats
}

func (a *api) builders() buildersResponse {
	log := logger.WithValues("service", "webAPI", "method", "buildersHandler")

	builders, err := a.store.Builders()
	if err != nil {
		log.Error(err, "failed getting builders")
		return buildersResponse{}
	}

	res := buildersResponse{
		Builders:         prettifyBuilders(builders),
		NumTotalBuilders: uint64(len(builders)),
		NumBuilders:      uint64(len(builders)),
	}

	return res
}

func (a *api) archiveHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := a.store.Archive(tw, w, slot); err != nil {
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

	log.Info("archived")
}

func (a *api) pruneHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) {
	log := logger.WithValues(
		"service", "webAPI",
		"method", "pruneHandler",
		"path", r.URL.Path,
	)

	slotStr := vars["slot"]

	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		log.Error(err, "invalid slot")
		http.Error(w, "invalid slot", http.StatusBadRequest)
		return
	}

	log.Info("pruning", "slot", slot)
	if err := a.store.Prune(slot); err != nil {
		log.Error(err, "failed pruning")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info("pruned", "slot", slot)
	w.WriteHeader(http.StatusOK)
}

func (a *api) backupHandler(w http.ResponseWriter, r *http.Request) {
	log := logger.WithValues(
		"service", "webAPI",
		"method", "backupHandler",
		"path", r.URL.Path,
	)

	bw := bufio.NewWriter(w)
	defer bw.Flush() // nolint:errcheck
	tw := tar.NewWriter(bw)
	defer tw.Close() // nolint:errcheck

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=backup_%d.tar", time.Now().Unix()))

	if err := a.store.Backup(tw); err != nil {
		log.Error(err, "failed backing up")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info("backed up")
}

func (a *api) internalBuilderHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) {
	log := logger.WithValues(
		"method", "internalBuilderHandler",
		"httpMethod", r.Method,
		"userAgent", r.UserAgent(),
		"query", r.URL.RawQuery,
	)

	pubKeyStr := vars["pubkey"]

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
	if err := a.store.SetBuilderStatus(pubKey, highPriority, blacklisted); err != nil {
		log.Error(err, "failed to set builder", "pubkey", pubKeyStr, "highPriority", highPriority, "blacklisted", blacklisted)
		http.Error(w, "failed to set builder", http.StatusInternalServerError)
		return
	}

	log.Info("set builder", "pubkey", pubKeyStr, "highPriority", highPriority, "blacklisted", blacklisted)
	httpJSONResponse(w, http.StatusOK, blockBuilderStatus{
		NewStatus: getBlockBuilderStatus(highPriority, blacklisted),
	})
}

type prettyDelivered struct {
	BlockNumber uint64
	NumTx       string
	BlockHash   types.Hash
	Slot        uint64
	Epoch       uint64
	Value       string
	Timestamp   string
	TimestampMs int64
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
	Builders         []prettyBuilder
	NumTotalBuilders uint64
	NumBuilders      uint64
}

type prettyBuilder struct {
	BlockBuilder
	CreatedAtStr            string
	UpdatedAtStr            string
	HighPriorityStr         string
	BlacklistedStr          string
	FinalDeliveredAtStr     string
	FinalSubmissionAtStr    string
	FirstDeliveredAtStr     string
	FirstSubmissionAtStr    string
	ShowDescription         bool
	InitialDeliveredSlot    string
	InitialSubmissionSlot   string
	FinalDeliveredSlot      string
	FinalSubmissionSlot     string
	ShowDeliveredLink       bool
	ShowFinalDeliveredLink  bool
	ShowFinalSubmissionLink bool
	ShowSubmissionLink      bool
	ShowFinalSubmissionAt   bool
	ShowFinalDeliveredAt    bool
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
