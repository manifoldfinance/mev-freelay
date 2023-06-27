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
	"archive/tar"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"time"
	"unsafe"

	"github.com/flashbots/go-boost-utils/types"
)

var (
	expireBidAfter      = 45 * time.Second
	expireBidTraceAfter = 120 * time.Second
)

type StoreSetter interface {
	UpsertBuilderSubmitted(pubKey types.PublicKey, slot uint64, submissionID string, simErr error) error
	UpsertBuilderDelivered(pubKey types.PublicKey, slot uint64, deliveredID string) error
	SetBuilderStatus(pubKey types.PublicKey, highPriority, blacklisted bool) error
	PutValidator(pubKey types.PublicKey, payload SignedValidatorRegistrationExtended) error
	PutBuilderBid(bidTrace BidTrace, getPayloadResponse GetPayloadResponse, getHeaderResponse GetHeaderResponse, receivedAt time.Time) error
	PutSubmitted(payload BidTraceExtended) error
	PutDelivered(payload DeliveredPayload) error
	PutMissed(payload MissedPayload) error
	SetLatestSlot(slot uint64) error
	Prune(slot uint64) error
	Close()
	StoreGetter
}

type StoreGetter interface {
	IsKnownBuilder(pubKey types.PublicKey) (bool, error)
	Builder(pubKey types.PublicKey) (*BlockBuilder, error)
	Builders() ([]BlockBuilder, error)
	CountValidators() (uint64, error)
	Validators() ([]types.SignedValidatorRegistration, error)
	Validator(pubKey types.PublicKey) (*types.SignedValidatorRegistration, error)
	ValidatorExtended(pubKey types.PublicKey) (*SignedValidatorRegistrationExtended, error)
	Delivered(query ProposerPayloadQuery) ([]BidTraceReceived, error)
	Submitted(query BuilderBlockQuery) ([]BidTraceReceived, error)
	Executed(slot uint64, proposerKey types.PublicKey, blockHash types.Hash) (*GetPayloadResponse, error)
	BidTrace(slot uint64, proposerKey types.PublicKey, blockHash types.Hash) (*BidTrace, error)
	BestBid(slot uint64, parentHash, proposerKey string) (*GetHeaderResponse, error)
	DeliveredCount() (uint64, error)
	LatestSlot() (uint64, error)
	Archive(tw *tar.Writer, w http.ResponseWriter, slot uint64) error
	Backup(tw *tar.Writer) error
}

type StoreKeeper interface {
	StoreSetter
	StoreGetter
	InsertBlockBuilder(BlockBuilder) error
}

func intToByteArray[T uint64 | int64](i T) []byte {
	var b []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh.Len = 8
	sh.Cap = 8
	sh.Data = uintptr(unsafe.Pointer(&i))

	return b[:]
}

func byteArrayToInt[T uint64 | int64](b []byte) T {
	return *(*T)(unsafe.Pointer(&b[0]))
}

func prefixKey(n uint64) string {
	return fmt.Sprintf("%018d", n)
}

func prefixLongKey(n uint64, str, str2 string) string {
	return fmt.Sprintf("%018d_%s_%s", n, str, str2)
}

func prefixWithZeroAndLimit(n *big.Int, length int) string {
	s := n.String()
	if len(s) > length {
		s = s[:length]
	} else {
		s = fmt.Sprintf("%0*d", length, n)
	}
	return s
}
