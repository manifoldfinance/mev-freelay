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
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPrefixWithZeroAndLimit(t *testing.T) {
	n := big.NewInt(1234567)
	p := prefixWithZeroAndLimit(n, 3)
	require.Equal(t, "123", p)

	n = big.NewInt(12)
	p = prefixWithZeroAndLimit(n, 8)
	require.Equal(t, "00000012", p)
}

func random20Bytes() (b [20]byte) {
	cryptorand.Read(b[:]) // nolint: errcheck
	return b
}

func random48Bytes() (b [48]byte) {
	cryptorand.Read(b[:]) // nolint: errcheck
	return b
}

func random96Bytes() (b [96]byte) {
	cryptorand.Read(b[:]) // nolint: errcheck
	return b
}

func random32Bytes() (b [32]byte) {
	cryptorand.Read(b[:]) // nolint: errcheck
	return b
}

func random64Bytes() (b [64]byte) {
	cryptorand.Read(b[:]) // nolint: errcheck
	return b
}

func random256Bytes() (b [256]byte) {
	cryptorand.Read(b[:]) // nolint: errcheck
	return b
}

func random512Bytes() (b [512]byte) { // nolint: unused
	cryptorand.Read(b[:]) // nolint: errcheck
	return b
}

func newTestStorePrefix() string {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("test_%d_db", rand.Int())
}
