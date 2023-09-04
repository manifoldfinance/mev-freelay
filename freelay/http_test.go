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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NYTimes/gziphandler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapper(t *testing.T) {
	s := struct {
		Text string `json:"text"`
	}{Text: "Wrapper OK"}
	b, _ := json.Marshal(s)

	h := func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var s struct{ Text string }
			err := json.NewDecoder(r.Body).Decode(&s)
			require.NoError(t, err)
			require.Equal(t, "Wrapper OK", s.Text)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Wrapper Works")) //nolint:errcheck
		}
	}

	hgzip := gziphandler.GzipHandler(h())
	w := wrapper(hgzip)

	// gzip
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/", io.NopCloser(bytes.NewReader(b)))
	req.Header.Set("Accept-Encoding", "gzip")
	w.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Decompress the gzipped response body
	res, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	assert.Equal(t, "Wrapper Works", string(res))

	// no gzip
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/", io.NopCloser(bytes.NewReader(b)))
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	cancel()
	w.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	res, _ = io.ReadAll(rr.Body)
	assert.Equal(t, "Wrapper Works", string(res))
}
