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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	buildercapella "github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimulateBlockSubmission(t *testing.T) {
	var (
		wg   = &sync.WaitGroup{}
		b    jsonrpcMessage
		host = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&b))
			defer r.Body.Close() //nolint:errcheck

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":true}`)) //nolint:errcheck
			wg.Done()
		}))
		ctx     = context.Background()
		payload = &BuilderBlockValidationRequest{
			BuilderSubmitBlockRequest: BuilderSubmitBlockRequest{
				Capella: &buildercapella.SubmitBlockRequest{
					Signature:        phase0.BLSSignature(random96Bytes()),
					Message:          &apiv1.BidTrace{},
					ExecutionPayload: &consensuscapella.ExecutionPayload{},
				},
			},
		}
	)
	wg.Add(1)
	defer host.Close()
	err := simulateBlockSubmission(ctx, payload, host.URL)
	wg.Wait()
	require.NoError(t, err)
	assert.Equal(t, "flashbots_validateBuilderSubmissionV2", b.Method)
	assert.Equal(t, "2.0", b.Version)
	id, err := b.ID.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, []byte("1"), id)
	assert.Len(t, b.Params, 1)
	assert.Equal(t, payload.Signature().String(), b.Params[0].(map[string]interface{})["signature"].(string))
}
