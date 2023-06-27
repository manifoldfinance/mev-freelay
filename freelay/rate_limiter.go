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
	"sync"
	"time"
)

type RateLimiter interface {
	Wait(ctx context.Context, key string) error
	Close(key string)
}

func NewRateLimiter(max uint64, d time.Duration) RateLimiter {
	if max == 0 {
		return &noRateLimiter{}
	}
	return newRateLimiter(max, d)
}

type noRateLimiter struct{}

func (i *noRateLimiter) Wait(ctx context.Context, key string) error {
	return nil
}

func (i *noRateLimiter) Close(key string) {}

type rateLimiter struct {
	keys map[string]*rateLimiterTimestamp
	max  uint64
	cond *sync.Cond
}

type rateLimiterTimestamp struct {
	count     uint64
	timestamp time.Time
}

func newRateLimiter(max uint64, d time.Duration) *rateLimiter {
	r := rateLimiter{
		keys: make(map[string]*rateLimiterTimestamp),
		max:  max,
		cond: sync.NewCond(&sync.Mutex{}),
	}
	go func() {
		for {
			time.Sleep(d / 2)
			r.clearOldKeys(d)
		}
	}()

	return &r
}

func (i *rateLimiter) clearOldKeys(d time.Duration) {
	i.cond.L.Lock()
	defer i.cond.L.Unlock()
	for k, v := range i.keys {
		if v.count == 0 && time.Since(v.timestamp) > d {
			delete(i.keys, k)
		}
	}
}

func (i *rateLimiter) Wait(ctx context.Context, key string) error {
	i.cond.L.Lock()
	defer i.cond.L.Unlock()
	l, exists := i.keys[key]

	if !exists {
		i.keys[key] = &rateLimiterTimestamp{
			count:     1,
			timestamp: time.Now(),
		}
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	for l.count >= i.max {
		i.cond.Wait()
	}

	l.count++
	return nil
}

func (i *rateLimiter) Close(key string) {
	i.cond.L.Lock()
	defer i.cond.L.Unlock()
	i.keys[key].count--
	i.cond.Broadcast()
}
