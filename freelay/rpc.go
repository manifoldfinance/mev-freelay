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
)

func simulateBlockSubmission(ctx context.Context, payload *BuilderBlockValidationRequest, host string) error {
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

	resp, err := sendrpcHTTP(ctx, host, msg)
	if err != nil {
		return fmt.Errorf("could not send rpc: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("rpc error: %v", resp.Error)
	}

	return nil
}

func sendrpcHTTP(ctx context.Context, host string, msgs jsonrpcMessage) (*jsonrpcMessage, error) {
	body, err := json.Marshal(msgs)
	if err != nil {
		return nil, fmt.Errorf("could not marshal messages: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}

	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var respmsgs jsonrpcMessage
	if err := json.NewDecoder(resp.Body).Decode(&respmsgs); err != nil {
		return nil, fmt.Errorf("could not decode response: %w", err)
	}

	return &respmsgs, nil
}

type jsonrpcMessage struct {
	Version string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
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
