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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/r3labs/sse/v2"
	"go.uber.org/atomic"
	"gopkg.in/cenkalti/backoff.v1"
)

const (
	syncTimeoutSec = 5
)

// Swagger Docs: https://ethereum.github.io/beacon-APIs/#/Beacon
type MultiBeacon interface {
	Genesis() (*GenesisInfo, error)
	Validators(headSlot uint64) (*KnownValidatorsResponse, error)
	BestSyncingNode() (*SyncNodeResponse, error)
	ProposerDuties(epoch uint64) (*ProposerDutiesResponse, error)
	SubscribeToHeadEvents(slot chan HeadEvent)
	SubscribeToPayloadAttributesEvents(payload chan PayloadAttributesEvent)
	Randao(slot uint64) (*RandaoResponse, error)
	PublishBlock(block *SignedBeaconBlock) error
	BlockBySlot(slot uint64) (*BeaconBlockResponse, error)
	ForkSchedule() (*ForkScheduleResponse, error)
	Withdrawals(slot uint64) (*WithdrawalsResponse, error)
}

type multiBeacon struct {
	beacons         []beacon
	bestBeaconIndex atomic.Int64
	log             logger.Logger
}

type beacon struct {
	uri              string
	safeURI          string
	syncStatusClient *http.Client
	validatorsClient *http.Client
	log              logger.Logger
}

func NewMultiBeacon(beaconURIs []string, validatorsTimeout uint64) *multiBeacon {
	beacons := make([]beacon, 0)
	for _, uri := range beaconURIs {
		beacons = append(beacons, *newBeacon(uri, validatorsTimeout))
	}

	return &multiBeacon{
		beacons:         beacons,
		bestBeaconIndex: *atomic.NewInt64(0),
		log:             logger.WithValues("module", "multiBeacon"),
	}
}

func (mb *multiBeacon) beaconsByLastResponse() []beacon {
	indx := mb.bestBeaconIndex.Load()
	if indx == 0 {
		return mb.beacons
	}
	beacons := make([]beacon, len(mb.beacons))
	copy(beacons, mb.beacons)
	beacons[0], beacons[indx] = beacons[indx], beacons[0]
	return beacons
}

func (mb *multiBeacon) beaconsByLeastUsed() []beacon {
	last := mb.beaconsByLastResponse()
	beacons := make([]beacon, len(last))

	for i := 0; i < len(last); i++ {
		beacons[i] = last[len(last)-i-1]
	}

	return beacons
}

func (mb *multiBeacon) Validators(headSlot uint64) (*KnownValidatorsResponse, error) {
	beacons := mb.beaconsByLeastUsed()
	for i, b := range beacons {
		mb.log.Info("getting validators", "uri", b.safeURI, "headSlot", headSlot)
		validators, err := b.Validators(headSlot)
		if err != nil {
			mb.log.Error(err, "error getting validators", "uri", b.safeURI, "headSlot", headSlot)
			continue
		}
		mb.log.Info("got validators", "uri", b.safeURI, "headSlot", headSlot)
		mb.bestBeaconIndex.Store(int64(i))
		return validators, nil
	}
	return nil, ErrAllBeaconsFailedGetValidators
}

func (mb *multiBeacon) Genesis() (*GenesisInfo, error) {
	var (
		err error
		res *GenesisInfo
	)
	beacons := mb.beaconsByLastResponse()
	for i, b := range beacons {
		res, err = b.Genesis()
		if err != nil {
			continue
		}

		mb.bestBeaconIndex.Store(int64(i))
		return res, nil
	}
	return nil, err
}

func (mb *multiBeacon) BestSyncingNode() (*SyncNodeResponse, error) {
	beacons := mb.beaconsByLastResponse()
	var bestSync *SyncNodeResponse
	for _, b := range beacons {
		resp, err := b.SyncStatus()
		if err != nil {
			mb.log.Error(err, "error getting sync status", "uri", b.safeURI)
			continue
		}

		if resp == nil {
			mb.log.Info("empty response sync status", "uri", b.safeURI)
			continue
		}

		if resp.Data.IsSyncing {
			continue
		}

		if bestSync == nil {
			bestSync = resp
		}

		if bestSync.Data.HeadSlot < resp.Data.HeadSlot {
			bestSync = resp
		}

		if resp.Data.SyncDistance <= 6 {
			break
		}
	}

	if bestSync == nil {
		return nil, ErrNoBeaconSynced
	}

	return bestSync, nil
}

func (mb *multiBeacon) ProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	beacons := mb.beaconsByLastResponse()
	for i, beacon := range beacons {
		duties, err := beacon.ProposerDuties(epoch)
		if err != nil {
			mb.log.Error(err, "error getting proposer duties", "uri", beacon.safeURI)
			continue
		}
		mb.bestBeaconIndex.Store(int64(i))
		return duties, nil
	}
	return nil, ErrAllBeaconsFailedGetProposerDuties
}

func (mb *multiBeacon) SubscribeToHeadEvents(slot chan HeadEvent) {
	for _, b := range mb.beacons {
		go b.SubscribeToHeadEvents(slot)
	}
}

func (mb *multiBeacon) SubscribeToPayloadAttributesEvents(payload chan PayloadAttributesEvent) {
	for _, b := range mb.beacons {
		go b.SubscribeToPayloadAttributesEvents(payload)
	}
}

func (mb *multiBeacon) Randao(slot uint64) (*RandaoResponse, error) {
	beacons := mb.beaconsByLastResponse()
	for i, beacon := range beacons {
		randao, err := beacon.Randao(slot)
		if err != nil {
			mb.log.Error(err, "error getting randao", "uri", beacon.safeURI, "slot", slot)
			continue
		}
		mb.bestBeaconIndex.Store(int64(i))
		return randao, nil
	}
	return nil, ErrAllBeaconsFailedGetRandao
}

func (mb *multiBeacon) PublishBlock(block *SignedBeaconBlock) error {
	beacons := mb.beaconsByLastResponse()
	results := make(chan error, len(beacons))
	for _, b := range beacons {
		go func(_b beacon) {
			mb.log.Info("publishing block", "uri", _b.safeURI, "block", block)
			err := _b.PublishBlock(block)
			if err != nil {
				mb.log.Error(err, "error publishing block", "uri", _b.safeURI)
			}
			results <- err
		}(b)
	}

	for i := 0; i < len(beacons); i++ {
		if err := <-results; err == nil {
			mb.bestBeaconIndex.Store(int64(i))
			mb.log.Info("block published", "block", block)
			return nil
		}
	}

	mb.log.Info("all beacons failed to publish block", "block", block)
	return ErrAllBeaconsFailedPublishBlock
}

func (mb *multiBeacon) BlockBySlot(slot uint64) (*BeaconBlockResponse, error) {
	beacons := mb.beaconsByLastResponse()
	for i, beacon := range beacons {
		block, err := beacon.BlockBySlot(slot)
		if err != nil {
			mb.log.Error(err, "error getting block by slot", "uri", beacon.safeURI, "slot", slot)
			continue
		}
		mb.bestBeaconIndex.Store(int64(i))
		return block, nil
	}
	return nil, ErrAllBeaconsFailedGetBlockBySlot
}

func (mb *multiBeacon) ForkSchedule() (*ForkScheduleResponse, error) {
	beacons := mb.beaconsByLastResponse()
	for i, beacon := range beacons {
		fork, err := beacon.ForkSchedule()
		if err != nil {
			mb.log.Error(err, "error getting fork schedule", "uri", beacon.safeURI)
			continue
		}
		mb.bestBeaconIndex.Store(int64(i))
		return fork, nil
	}
	return nil, ErrAllBeaconsFailedGetForkSchedule
}

func (mb *multiBeacon) Withdrawals(slot uint64) (*WithdrawalsResponse, error) {
	beacons := mb.beaconsByLastResponse()
	for i, beacon := range beacons {
		withdrawals, err := beacon.Withdrawals(slot)
		if err != nil {
			mb.log.Error(err, "error getting withdrawals", "uri", beacon.safeURI, "slot", slot)
			if strings.Contains(err.Error(), "Withdrawals not enabled before capella") {
				break
			}
			continue
		}
		mb.bestBeaconIndex.Store(int64(i))
		return withdrawals, nil
	}
	return nil, ErrAllBeaconsFailedGetWithdrawals
}

func newBeacon(uri string, validatorsTimeout uint64) *beacon {
	return &beacon{
		uri:     uri,
		safeURI: hideCredentialsFromURL(uri),
		syncStatusClient: &http.Client{
			Timeout: time.Duration(syncTimeoutSec) * time.Second,
		},
		validatorsClient: &http.Client{
			Timeout: time.Duration(validatorsTimeout) * time.Second,
		},
		log: logger.WithValues("module", "beacon"),
	}
}

func (b *beacon) join(pth string) string {
	uri, err := url.JoinPath(b.uri, pth)
	if err != nil {
		b.log.Error(err, "error joining path", "uri", b.safeURI, "path", pth)
		return fmt.Sprintf("%s%s", b.uri, pth)
	}

	un, err := url.PathUnescape(uri)
	if err != nil {
		b.log.Error(err, "error unescaping path", "uri", b.safeURI, "path", pth)
		return fmt.Sprintf("%s%s", b.uri, pth)
	}
	return un
}

func (b *beacon) Genesis() (*GenesisInfo, error) {
	resp := new(GenesisResponse)
	_, err := sendHTTP(http.DefaultClient, b.join("/eth/v1/beacon/genesis"), http.MethodGet, nil, &resp)
	return &resp.Data, err
}

func (b *beacon) Validators(headSlot uint64) (*KnownValidatorsResponse, error) {
	resp := new(KnownValidatorsResponse)
	_, err := sendHTTP(b.validatorsClient, b.join(fmt.Sprintf("/eth/v1/beacon/states/%d/validators?status=active,pending", headSlot)), http.MethodGet, nil, &resp)
	if err != nil {
		return nil, err
	}

	return resp, err
}

func (b *beacon) SyncStatus() (*SyncNodeResponse, error) {
	resp := new(SyncNodeResponse)
	_, err := sendHTTP(b.syncStatusClient, b.join("/eth/v1/node/syncing"), http.MethodGet, nil, &resp)
	return resp, err
}

func (b *beacon) ProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	resp := new(ProposerDutiesResponse)
	_, err := sendHTTP(http.DefaultClient, b.join(fmt.Sprintf("/eth/v1/validator/duties/proposer/%d", epoch)), http.MethodGet, nil, &resp)
	return resp, err
}

func (b *beacon) SubscribeToHeadEvents(slot chan HeadEvent) {
	url := b.join("/eth/v1/events?topics=head")

	client := sse.NewClient(url)
	client.ReconnectStrategy = &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.5,
		MaxInterval:         2 * time.Second,
		MaxElapsedTime:      0,
		Clock:               backoff.SystemClock,
	}

	client.ReconnectNotify = func(err error, d time.Duration) {
		b.log.Error(err, "reconnecting to head events SSE", "backoff", d.Seconds(), "uri", b.safeURI)
	}

	if err := client.SubscribeRaw(func(msg *sse.Event) {
		var h HeadEvent
		if err := json.Unmarshal(msg.Data, &h); err != nil {
			b.log.Error(err, "error unmarshalling head event")
			return
		}
		b.log.Info("new beacon slot event", "slot", h.Slot)
		slot <- h
	}); err != nil {
		b.log.Error(err, "error subscribing to head events")
	}
}

func (b *beacon) SubscribeToPayloadAttributesEvents(payload chan PayloadAttributesEvent) {
	url := b.join("/eth/v1/events?topics=payload_attributes")

	client := sse.NewClient(url)
	client.ReconnectStrategy = &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.5,
		MaxInterval:         2 * time.Second,
		MaxElapsedTime:      0,
		Clock:               backoff.SystemClock,
	}

	client.ReconnectNotify = func(err error, d time.Duration) {
		b.log.Error(err, "reconnecting payloads attributes events SSE", "backoff", d.Seconds(), "uri", b.safeURI)
	}

	if err := client.SubscribeRaw(func(msg *sse.Event) {
		var p PayloadAttributesEvent
		if err := json.Unmarshal(msg.Data, &p); err != nil {
			b.log.Error(err, "error unmarshalling payload attributes event")
			return
		}
		b.log.Info("new payload attributes event", "proposalSlot", p.Data.ProposalSlot)
		payload <- p
	}); err != nil {
		b.log.Error(err, "error subscribing to payload attributes events")
	}
}

func (b *beacon) Randao(slot uint64) (*RandaoResponse, error) {
	resp := new(RandaoResponse)
	_, err := sendHTTP(http.DefaultClient, b.join(fmt.Sprintf("/eth/v1/beacon/states/%d/randao", slot)), http.MethodGet, nil, &resp)
	return resp, err
}

func (b *beacon) PublishBlock(block *SignedBeaconBlock) error {
	code, err := sendHTTP(http.DefaultClient, b.join("/eth/v1/beacon/blocks"), http.MethodPost, block, nil)
	if err != nil {
		return err
	}

	if code == http.StatusAccepted {
		return ErrBlockBroadcastedButFailedIntegration
	}

	return nil
}

func (b *beacon) BlockBySlot(slot uint64) (*BeaconBlockResponse, error) {
	resp := new(BeaconBlockResponse)
	_, err := sendHTTP(http.DefaultClient, b.join(fmt.Sprintf("/eth/v2/beacon/blocks/%d", slot)), http.MethodGet, nil, &resp)
	return resp, err
}

func (b *beacon) ForkSchedule() (*ForkScheduleResponse, error) {
	resp := new(ForkScheduleResponse)
	_, err := sendHTTP(http.DefaultClient, b.join("/eth/v1/config/fork_schedule"), http.MethodGet, nil, &resp)
	return resp, err
}

func (b *beacon) Withdrawals(slot uint64) (*WithdrawalsResponse, error) {
	resp := new(WithdrawalsResponse)
	_, err := sendHTTP(http.DefaultClient, b.join(fmt.Sprintf("/eth/v1/beacon/states/%d/withdrawals", slot)), http.MethodGet, nil, &resp)
	return resp, err
}

type KnownValidatorsResponse struct {
	Data                []ValidatorResponseEntry `json:"data"`
	ExecutionOptimistic bool                     `json:"execution_optimistic"`
	Finalized           bool                     `json:"finalized"`
}

type ValidatorResponseEntry struct {
	Index     uint64                         `json:"index,string"`
	Balance   int64                          `json:"balance,string"`
	Status    string                         `json:"status"`
	Validator ValidatorResponseValidatorData `json:"validator"`
}

type ValidatorResponseValidatorData struct {
	Pubkey string `json:"pubkey"`
}

type GenesisResponse struct {
	Data GenesisInfo
}

type GenesisInfo struct {
	GenesisTime           uint64 `json:"genesis_time,string"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	GenesisForkVersion    string `json:"genesis_fork_version"`
}

type SyncNodeResponse struct {
	Data SyncNode
}

type SyncNode struct {
	HeadSlot     uint64 `json:"head_slot,string"`
	IsSyncing    bool   `json:"is_syncing"`
	SyncDistance uint64 `json:"sync_distance,string"`
	IsOptimistic bool   `json:"is_optimistic"`
}

type ProposerDutiesResponse struct {
	Data []ProposerDuty
}

type ProposerDuty struct {
	Pubkey         string `json:"pubkey"`
	Slot           uint64 `json:"slot,string"`
	ValidatorIndex uint64 `json:"validator_index,string"`
}

type HeadEvent struct {
	Slot  uint64 `json:"slot,string"`
	Block string `json:"block"`
	State string `json:"state"`
}

type PayloadAttributesEvent struct {
	Version string                     `json:"version"`
	Data    PayloadAttributesEventData `json:"data"`
}

type PayloadAttributesEventData struct {
	ProposerIndex     uint64            `json:"proposer_index,string"`
	ProposalSlot      uint64            `json:"proposal_slot,string"`
	ParentBlockNumber uint64            `json:"parent_block_number,string"`
	ParentBlockRoot   string            `json:"parent_block_root"`
	ParentBlockHash   string            `json:"parent_block_hash"`
	PayloadAttributes PayloadAttributes `json:"payload_attributes"`
}

type PayloadAttributes struct {
	Timestamp             uint64                         `json:"timestamp,string"`
	PrevRandao            string                         `json:"prev_randao"`
	SuggestedFeeRecipient string                         `json:"suggested_fee_recipient"`
	Withdrawals           []*consensuscapella.Withdrawal `json:"withdrawals"`
}

type RandaoResponse struct {
	Data Randao
}

type Randao struct {
	Randao string `json:"randao"`
}

type ForkScheduleResponse struct {
	Data []ForkSchedule `json:"data"`
}

type ForkSchedule struct {
	PreviousVersion string `json:"previous_version"`
	CurrentVersion  string `json:"current_version"`
	Epoch           uint64 `json:"epoch,string"`
}

type WithdrawalsResponse struct {
	Data WithdrawalsData `json:"data"`
}

type WithdrawalsData struct {
	Withdrawals []*consensuscapella.Withdrawal `json:"withdrawals"`
}

type BeaconBlockResponse struct {
	Data    SignedBeaconBlock `json:"data"`
	Version string            `json:"version"`
}

func sendHTTP(client *http.Client, uri string, method string, msg, dst any) (int, error) {
	var req *http.Request
	if msg != nil {
		payload, err := json.Marshal(msg)
		if err != nil {
			return 0, err
		}

		req, err = http.NewRequest(method, uri, io.NopCloser(bytes.NewReader(payload)))
		if err != nil {
			return 0, err
		}
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil }
		req.Header.Add("Content-Type", "application/json")
	} else {
		var err error
		req, err = http.NewRequest(method, uri, nil)
		if err != nil {
			return 0, err
		}
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }
	}

	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, err
	}

	if res.StatusCode >= http.StatusMultipleChoices {
		ec := &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{}
		if err := json.Unmarshal(body, &ec); err != nil {
			return res.StatusCode, fmt.Errorf("error unmarshaling error response: %w", err)
		}
		return res.StatusCode, fmt.Errorf("error response: %s", ec.Message)
	}

	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			return res.StatusCode, fmt.Errorf("error unmarshaling response: %w", err)
		}
	}

	return res.StatusCode, nil
}
