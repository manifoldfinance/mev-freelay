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
	runtime "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manifoldfinance/mev-freelay/logger"
)

var gzPool = sync.Pool{
	New: func() interface{} {
		w := gzip.NewWriter(io.Discard)
		return w
	},
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func wrapper(f http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		receivedAt := time.Now().UTC().UnixMilli()
		// panic recovery
		defer func() {
			if re := recover(); re != nil {
				logger.Error(errors.New("an unexpected error"), "panic", "error", fmt.Sprintf("%v", re), "stack", string(runtime.Stack()))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()

		defer func() {
			if r.RequestURI != "/eth/v1/builder/status" {
				ip := userIP(r)
				logger.Info("request", "remote_addr", ip, "uri", r.RequestURI)
			}
		}()

		defer func() {
			checkContext(r.Context(), r.RequestURI, r.Method)
		}()

		r.Header.Set("X-Req-Received-At", strconv.FormatInt(receivedAt, 10))
		// in case body is nil we set up an empty reader
		if r.Body == nil {
			r.Body = io.NopCloser(bytes.NewReader([]byte{}))
		}

		w.Header().Add("Content-Type", "application/json")

		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzPool.Get().(*gzip.Writer)

			defer gzPool.Put(gz)
			defer gz.Close() //nolint:errcheck
			gz.Reset(w)

			f.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gz}, r)
			return
		}

		f.ServeHTTP(w, r)
	}
}

func checkContext(ctx context.Context, pth, method string) {
	select {
	case <-ctx.Done():
		switch ctx.Err() {
		case context.Canceled:
			logger.Info("context request cancelled by force. whole process is complete", "path", pth, "method", method)
		default:
			logger.Info("context errored", "error", ctx.Err(), "path", pth, "method", method)
		}
	default:
	}
}

func httpJSONResponse(w http.ResponseWriter, code int, body interface{}) {
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.Error(err, "failed to encode response body")
		http.Error(w, "failed to encode response body", http.StatusInternalServerError)
	}
}

func httpJSONError(w http.ResponseWriter, code int, msg string) {
	httpJSONResponse(w, code, JSONError{
		Code:    code,
		Message: msg,
	})
}
