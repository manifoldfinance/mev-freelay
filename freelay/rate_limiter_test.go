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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter(t *testing.T) {
	key := "test"
	limiter := newRateLimiter(2, time.Duration(4*time.Millisecond))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := limiter.Wait(r.Context(), key); err != nil {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		defer limiter.Close(key)
		time.Sleep(time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	wg := sync.WaitGroup{}
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			rr := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
			wg.Done()
		}()
	}
	wg.Wait()

	// test with timed out context
	limiter = newRateLimiter(2, time.Duration(20*time.Millisecond))
	wg = sync.WaitGroup{}
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(indx int) {
			rr := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			if indx < 2 {
				h.ServeHTTP(rr, req)
				assert.Equal(t, http.StatusOK, rr.Code)
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
				time.Sleep(5 * time.Millisecond)
				h.ServeHTTP(rr, req.WithContext(ctx))
				cancel()
				assert.Equal(t, http.StatusTooManyRequests, rr.Code)
			}

			wg.Done()
		}(i)
	}
	wg.Wait()
}
