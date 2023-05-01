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
	"regexp"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
)

func hideCredentialsFromURL(url string) string {
	// Create a regular expression to match the "user:pass@" portion of the URL
	regex := regexp.MustCompile(`^(.*:\/\/)([^:]+:[^@]+@)(.*)$`)

	// Replace the "user:pass@" portion of the URL with a placeholder string
	placeholder := "$1<redacted>@$3"
	result := regex.ReplaceAllString(url, placeholder)

	return result
}

func reverseBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	// Reverse byte order (big-endian to little-endian)
	for i := 0; i < len(out)/2; i++ {
		j := len(out) - i - 1
		out[i], out[j] = out[j], out[i]
	}

	return out
}

func uint256ToU256(in *uint256.Int) types.U256Str {
	vl := types.U256Str{}
	if in == nil {
		return vl
	}
	// Bytes returned as a big-endian byte array
	// FromSlice receives bytes order as it is, but
	// BigInt reverses the order of bytes to little-endian
	vl.FromSlice(reverseBytes(in.Bytes())) // nolint:errcheck
	return vl
}
