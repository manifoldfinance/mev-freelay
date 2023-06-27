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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/manifoldfinance/mev-freelay/logger"
)

type BuilderBlockSimulator interface {
	SimulateBlockSubmission(ctx context.Context, payload *BuilderBlockValidationRequest) error
}

type builderBlockSimulate struct {
	client   *http.Client
	addr     string
	safeAddr string
}

func NewBuilderBlockSimulator(timeout time.Duration, addr string) *builderBlockSimulate {
	return &builderBlockSimulate{
		client:   &http.Client{Timeout: timeout},
		addr:     addr,
		safeAddr: hideCredentialsFromURL(addr),
	}
}

func (b *builderBlockSimulate) SimulateBlockSubmission(ctx context.Context, payload *BuilderBlockValidationRequest) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error: %w", err)
	}

	var msg jsonrpcMessage
	if payload.Capella != nil {
		msg = jsonrpcMessage{
			Version: "2.0",
			Method:  "flashbots_validateBuilderSubmissionV2",
			Params:  []interface{}{payload},
			ID:      json.RawMessage(`1`),
		}
	} else {
		return ErrInvalidPayloadSimulate
	}

	bidTrace := payload.Message()
	resp, err := sendrpcHTTP(b.client, b.addr, msg, bidTrace.Slot, bidTrace.BlockHash)
	if err != nil {
		return fmt.Errorf("could not send rpc: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("rpc error: %v", resp.Error)
	}

	return nil
}

func sendrpcHTTP(client *http.Client, host string, msgs jsonrpcMessage, slot uint64, blockHash types.Hash) (*jsonrpcMessage, error) {
	body, err := json.Marshal(msgs)
	if err != nil {
		return nil, fmt.Errorf("could not marshal messages: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, host, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}

	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-Request-ID", fmt.Sprintf("%d/%s", slot, blockHash.String()))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err, "could not read response bytes", "body", resp.Body)
		return nil, fmt.Errorf("could not read response bytes: %w", err)
	}

	respmsgs := new(jsonrpcMessage)
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(respmsgs); err != nil {
		logger.Error(err, "could not decode response", "body", string(raw))
		return nil, fmt.Errorf("could not decode response: %w", err)
	}

	return respmsgs, nil
}

type jsonrpcMessage struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  []interface{}   `json:"params,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}
type jsonrpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
