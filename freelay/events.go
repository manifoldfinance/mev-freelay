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
	"context"
	"math/big"
	"os"
	"time"

	eventsender "github.com/draganm/event-sender"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/manifoldfinance/mev-freelay/logger"
)

type EventSender interface {
	SendHeaderFetchedEvent(slot uint64, hash common.Hash, value *big.Int) error
	SendBlockUnblindedEvent(slot uint64, hash common.Hash, value *big.Int) error
	SendBlockSubmittedEvent(slot uint64, builder string, hash common.Hash, value *big.Int) error
	SendBlockSimulationFailedEvent(slot uint64, builder string, hash common.Hash, value *big.Int, err error) error
}

func NewEventSender(ctx context.Context, endpoint string) (EventSender, error) {
	if endpoint == "" {
		return newDummyEventSender(), nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		logger.Error(err, "failed to get hostname")
		return nil, err
	}

	return newEventSender(ctx, hostname, endpoint)
}

var etherFloat = big.NewFloat(params.Ether)

type eventSender struct {
	sender   *eventsender.EventSender
	hostname string
	endpoint string
}

func newEventSender(ctx context.Context, hostname, endpoint string) (*eventSender, error) {
	sender, err := eventsender.New(ctx, endpoint, 3000)
	if err != nil {
		return nil, err
	}

	logger.Info("configured event sink", "endpoint", endpoint)

	return &eventSender{
		sender:   sender,
		hostname: hostname,
		endpoint: endpoint,
	}, nil
}

func (e *eventSender) send(evt interface{}) error {
	if e.sender != nil {
		return e.sender.SendEvent(evt)
	}
	return nil
}

func (e *eventSender) SendHeaderFetchedEvent(slot uint64, hash common.Hash, value *big.Int) error {
	return e.send(event{
		Time:  time.Now(),
		Type:  "header_fetched",
		Relay: e.hostname,
		Slot:  slot,
		Hash:  hash,
		Value: toEth(value),
	})
}

func (e *eventSender) SendBlockUnblindedEvent(slot uint64, hash common.Hash, value *big.Int) error {
	return e.send(event{
		Time:  time.Now(),
		Type:  "block_unblinded",
		Relay: e.hostname,
		Slot:  slot,
		Hash:  hash,
		Value: toEth(value),
	})
}

func (e *eventSender) SendBlockSubmittedEvent(slot uint64, builder string, hash common.Hash, value *big.Int) error {
	return e.send(blockSubmitted{
		event: event{
			Time:  time.Now(),
			Type:  "block_submitted",
			Relay: e.hostname,
			Slot:  slot,
			Hash:  hash,
			Value: toEth(value),
		},
		Builder: builder,
	})
}

func (e *eventSender) SendBlockSimulationFailedEvent(slot uint64, builder string, hash common.Hash, value *big.Int, err error) error {
	return e.send(blockSimulationFailed{
		event: event{
			Time:  time.Now(),
			Type:  "block_simulation_failed",
			Relay: e.hostname,
			Slot:  slot,
			Hash:  hash,
			Value: toEth(value),
		},
		Builder: builder,
		Error:   err.Error(),
	})
}

type dummyEventSender struct{}

func newDummyEventSender() *dummyEventSender {
	return &dummyEventSender{}
}

func (d *dummyEventSender) SendHeaderFetchedEvent(slot uint64, hash common.Hash, value *big.Int) error {
	return nil
}
func (d *dummyEventSender) SendBlockUnblindedEvent(slot uint64, hash common.Hash, value *big.Int) error {
	return nil
}
func (d *dummyEventSender) SendBlockSubmittedEvent(slot uint64, builder string, hash common.Hash, value *big.Int) error {
	return nil
}
func (d *dummyEventSender) SendBlockSimulationFailedEvent(slot uint64, builder string, hash common.Hash, value *big.Int, err error) error {
	return nil
}

type event struct {
	Time  time.Time   `json:"time"`
	Type  string      `json:"type"`
	Relay string      `json:"relay"`
	Slot  uint64      `json:"slot"`
	Hash  common.Hash `json:"hash"`
	Value float64     `json:"value"`
}

type blockSubmitted struct {
	event
	Builder string `json:"builder"`
}

type blockSimulationFailed struct {
	event
	Builder string `json:"builder"`
	Error   string `json:"error"`
}

func toEth(v *big.Int) float64 {
	fl := big.NewFloat(0)
	fl.SetInt(v)
	fl.Quo(fl, etherFloat)
	fv, _ := fl.Float64()
	return fv
}
