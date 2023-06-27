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
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestInternalV1BuilderBaseHandler(t *testing.T) {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	var (
		a          = newTestAPI(t)
		builderKey = types.PublicKey{0x12}
		pth        = fmt.Sprintf("/internal/v1/builder/%s", builderKey.String())
		bl         = blockBuilderReqBody{
			HighPriority: false,
			Blacklisted:  true,
		}
		body, _ = json.Marshal(bl)
	)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, pth, io.NopCloser(bytes.NewReader(body)))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := make(map[string]string)
		vars["pubkey"] = builderKey.String()
		a.internalBuilderHandler(w, r, vars)
	})
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var bbs2 blockBuilderStatus
	err := json.NewDecoder(rr.Body).Decode(&bbs2)
	require.NoError(t, err)
	require.Equal(t, "blacklisted", bbs2.NewStatus)
	gbb, err := a.store.Builder(builderKey)
	require.NoError(t, err)
	require.False(t, gbb.HighPriority)
	require.True(t, gbb.Blacklisted)
}

func newTestAPI(t *testing.T) *api {
	var (
		known         = NewKnownValidators()
		genesisTime   = uint64(time.Now().Unix())
		network       = "goerli"
		store, prefix = newTestPebbleDB(t)
		publicKey     = types.PublicKey{0x12}
	)

	t.Cleanup(func() {
		store.Close()
		cleanupTestPebbleDB(t, prefix)
	})

	return NewAPI(store, known, genesisTime, network, publicKey, trace.NewNoopTracerProvider().Tracer("webApi"))
}
