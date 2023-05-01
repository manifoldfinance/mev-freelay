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
	"bufio"
	"fmt"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	builderapi "github.com/attestantio/go-builder-client/api"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/draganm/bolted"
	"github.com/draganm/bolted/dbpath"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func TestCreateBackup(t *testing.T) {
	store, prefix := newTestStore(t)
	defer testStoreCleanup(t, store, prefix)
	defer os.RemoveAll(prefix) //nolint:errcheck

	w := httptest.NewRecorder()
	bw := bufio.NewWriter(w)
	defer bw.Flush() // nolint:errcheck
	tw := tar.NewWriter(bw)
	defer tw.Close() // nolint:errcheck

	err := CreateBackup(w, tw, store.DB(), prefix, prefix)
	require.NoError(t, err)
	require.Equal(t, "application/x-tar", w.Result().Header.Get("Content-Type"))
	re := regexp.MustCompile(`attachment; filename=backup_\d+.tar`)
	require.Regexp(t, re, w.Result().Header.Get("Content-Disposition"))
}

func TestCompact(t *testing.T) {
	prefix := newTestPrefix()

	db, err := bbolt.Open(joinDBPth(prefix, storeDBPth), 0666, nil)
	require.NoError(t, err)
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("root"))
		require.NoError(t, err)
		// Write 50MB of zeros to the database
		zeros := make([]byte, 50*1024*1024)
		if err := b.Put([]byte("zeros"), zeros); err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)
	db.Close() // nolint:errcheck

	store, err := NewStore(prefix)
	require.NoError(t, err)
	defer testStoreCleanup(t, store, prefix)

	for i := 0; i < 10; i++ {
		err := store.PutRegistrationValidator(
			types.PublicKey(random48Bytes()),
			SignedValidatorRegistrationExtended{
				SignedValidatorRegistration: types.SignedValidatorRegistration{
					Message: &types.RegisterValidatorRequestMessage{
						FeeRecipient: types.Address(random20Bytes()),
						Timestamp:    1234356,
						GasLimit:     278234191203,
						Pubkey:       types.PublicKey(random48Bytes()),
					},
					Signature: types.Signature(random96Bytes()),
				},
				Timestamp: time.Now().UTC(),
				IP:        "192.168.0.1",
			},
		)
		require.NoError(t, err)
	}

	var fileSize int64
	err = bolted.SugaredRead(store.db, func(tx bolted.SugaredReadTx) error {
		fileSize = tx.FileSize()
		return nil
	})
	require.NoError(t, err)
	require.Greater(t, fileSize, int64(0))

	err = bolted.SugaredWrite(store.db, func(tx bolted.SugaredWriteTx) error {
		tx.Delete(dbpath.ToPath("zeros"))
		return nil
	})
	require.NoError(t, err)

	store.Close()

	err = Compact(prefix)
	require.NoError(t, err)

	store, err = NewStore(prefix)
	require.NoError(t, err)
	var fileSizeAfterDelete int64
	err = bolted.SugaredRead(store.db, func(tx bolted.SugaredReadTx) error {
		fileSizeAfterDelete = tx.FileSize()
		return nil
	})
	require.NoError(t, err)
	require.Less(t, fileSizeAfterDelete, fileSize)
}

func TestArchive(t *testing.T) {
	exePayload := VersionedExecutedPayload{
		Capella: &builderapi.VersionedExecutionPayload{
			Version: consensusspec.DataVersionCapella,
			Capella: &consensuscapella.ExecutionPayload{
				ExtraData:     []byte{},
				BlockHash:     phase0.Hash32(random32Bytes()),
				ParentHash:    phase0.Hash32(random32Bytes()),
				Withdrawals:   []*consensuscapella.Withdrawal{},
				Transactions:  []consensusbellatrix.Transaction{},
				GasLimit:      100,
				GasUsed:       10,
				Timestamp:     100,
				BlockNumber:   1000,
				BaseFeePerGas: random32Bytes(),
			},
		},
		Timestamp: time.Now().UTC(),
	}

	subPayload := BidTraceExtended{
		BidTrace: BidTrace{
			BidTrace: types.BidTrace{
				Slot:                 1,
				BlockHash:            types.Hash(random32Bytes()),
				ProposerPubkey:       types.PublicKey(random48Bytes()),
				ParentHash:           types.Hash(random32Bytes()),
				ProposerFeeRecipient: types.Address(random20Bytes()),
				Value:                types.IntToU256(100),
				GasLimit:             100,
				GasUsed:              10,
			},
			BlockNumber: 1,
			NumTx:       1,
		},
		Timestamp: time.Now().UTC(),
	}

	store, prefix := newTestStore(t)
	defer testStoreCleanup(t, store, prefix)

	for i := 1; i <= 22; i++ {
		subPayload.Slot = uint64(i)
		subPayload.ExecutionPayloadKey = fmt.Sprintf("%d_%s_%s", subPayload.Slot, subPayload.ProposerPubkey, subPayload.BlockHash)
		subPayload.BlockNumber = uint64(i)
		err := store.PutBuilderBlockSubmissionsPayload(subPayload)
		require.NoError(t, err)
		err = store.PutExecutedPayload(subPayload.Slot, subPayload.ProposerPubkey, subPayload.BlockHash, exePayload)
		require.NoError(t, err)
	}

	w := httptest.NewRecorder()
	bw := bufio.NewWriter(w)
	defer bw.Flush() // nolint:errcheck
	tw := tar.NewWriter(bw)
	defer tw.Close() // nolint:errcheck
	err := Archive(store.DB(), tw, w, 11)
	require.NoError(t, err)
	require.Equal(t, "application/x-tar", w.Result().Header.Get("Content-Type"))
	require.Equal(t, "attachment; filename=slot_000000000000000001_000000000000000011.tar", w.Result().Header.Get("Content-Disposition"))

	// empty db for 204
	err = bolted.SugaredWrite(store.db, func(tx bolted.SugaredWriteTx) error {
		keys := make([]string, 0)
		for it := tx.Iterator(payloadExecutedMapPth); !it.IsDone(); it.Next() {
			keys = append(keys, it.GetKey())
		}

		for _, key := range keys {
			tx.Delete(payloadExecutedMapPth.Append(key))
		}
		return nil
	})
	require.NoError(t, err)
	err = bolted.SugaredWrite(store.db, func(tx bolted.SugaredWriteTx) error {
		keys := make([]string, 0)
		for it := tx.Iterator(payloadSubmissionsBlockHashMapPth); !it.IsDone(); it.Next() {
			keys = append(keys, it.GetKey())
		}
		for _, key := range keys {
			tx.Delete(payloadSubmissionsBlockHashMapPth.Append(key))
		}

		keys = make([]string, 0)
		for it := tx.Iterator(payloadSubmissionsBlockNumberMapPth); !it.IsDone(); it.Next() {
			keys = append(keys, it.GetKey())
		}
		for _, key := range keys {
			tx.Delete(payloadSubmissionsBlockNumberMapPth.Append(key))
		}

		keys = make([]string, 0)
		for it := tx.Iterator(payloadSubmissionsSlotMapPth); !it.IsDone(); it.Next() {
			keys = append(keys, it.GetKey())
		}
		for _, key := range keys {
			tx.Delete(payloadSubmissionsSlotMapPth.Append(key))
		}
		return nil
	})
	require.NoError(t, err)

	w2 := httptest.NewRecorder()
	bw2 := bufio.NewWriter(w2)
	defer bw2.Flush() // nolint:errcheck
	tw2 := tar.NewWriter(bw2)
	defer tw2.Close() // nolint:errcheck
	err = Archive(store.DB(), tw2, w2, 11)
	require.Equal(t, ErrNoArchivePayloadsFound, err)
	require.Equal(t, "application/x-tar", w2.Result().Header.Get("Content-Type"))
	require.Equal(t, "", w2.Result().Header.Get("Content-Disposition"))
}

func TestPrune(t *testing.T) {
	exePayload := VersionedExecutedPayload{
		Capella: &builderapi.VersionedExecutionPayload{
			Version: consensusspec.DataVersionCapella,
			Capella: &consensuscapella.ExecutionPayload{
				ExtraData:     []byte{},
				BlockHash:     phase0.Hash32(random32Bytes()),
				ParentHash:    phase0.Hash32(random32Bytes()),
				Withdrawals:   []*consensuscapella.Withdrawal{},
				Transactions:  []consensusbellatrix.Transaction{},
				GasLimit:      100,
				GasUsed:       10,
				Timestamp:     100,
				BlockNumber:   1000,
				BaseFeePerGas: random32Bytes(),
			},
		},
		Timestamp: time.Now().UTC(),
	}

	subPayload := BidTraceExtended{
		BidTrace: BidTrace{
			BidTrace: types.BidTrace{
				Slot:                 1,
				BlockHash:            types.Hash(random32Bytes()),
				ProposerPubkey:       types.PublicKey(random48Bytes()),
				ParentHash:           types.Hash(random32Bytes()),
				ProposerFeeRecipient: types.Address(random20Bytes()),
				Value:                types.IntToU256(100),
				GasLimit:             100,
				GasUsed:              10,
			},
			BlockNumber: 1,
			NumTx:       1,
		},
		Timestamp: time.Now().UTC(),
	}

	store, prefix := newTestStore(t)
	defer testStoreCleanup(t, store, prefix)

	proposers := make(map[uint64]types.PublicKey)
	hashes := make(map[uint64]types.Hash)
	for i := 1; i <= 11; i++ {
		proposers[uint64(i)] = types.PublicKey(random48Bytes())
		hashes[uint64(i)] = types.Hash(random32Bytes())
		subPayload.Slot = uint64(i)
		subPayload.BlockHash = hashes[uint64(i)]
		subPayload.ProposerPubkey = proposers[uint64(i)]
		subPayload.BlockNumber = uint64(i)
		subPayload.ExecutionPayloadKey = fmt.Sprintf("%d_%s_%s", subPayload.Slot, subPayload.ProposerPubkey, subPayload.BlockHash)
		err := store.PutBuilderBlockSubmissionsPayload(subPayload)
		require.NoError(t, err)
		err = store.PutExecutedPayload(uint64(i), proposers[uint64(i)], hashes[uint64(i)], exePayload)
		require.NoError(t, err)
	}

	for i := 14; i <= 22; i++ {
		proposers[uint64(i)] = types.PublicKey(random48Bytes())
		hashes[uint64(i)] = types.Hash(random32Bytes())
		subPayload.Slot = uint64(i)
		subPayload.BlockHash = hashes[uint64(i)]
		subPayload.ProposerPubkey = proposers[uint64(i)]
		subPayload.BlockNumber = uint64(i)
		subPayload.ExecutionPayloadKey = fmt.Sprintf("%d_%s_%s", subPayload.Slot, subPayload.ProposerPubkey, subPayload.BlockHash)
		err := store.PutBuilderBlockSubmissionsPayload(subPayload)
		require.NoError(t, err)
		err = store.PutExecutedPayload(uint64(i), proposers[uint64(i)], hashes[uint64(i)], exePayload)
		require.NoError(t, err)
	}

	err := Prune(store.DB(), 13)
	require.NoError(t, err)
	ex, err := store.ExecutedPayload(1, proposers[1], hashes[1])
	require.Error(t, err)
	require.Nil(t, ex)

	ex, err = store.ExecutedPayload(14, proposers[14], hashes[14])
	require.NoError(t, err)
	require.Equal(t, &GetPayloadResponse{Capella: exePayload.Capella}, ex)

	su, err := store.BlockSubmissionsPayload(BuilderBlockQuery{Slot: 1, Limit: 100})
	require.NoError(t, err)
	require.Len(t, su, 0)

	sb := subPayload
	sb.Slot = 14
	sb.BlockHash = hashes[14]
	sb.ProposerPubkey = proposers[14]
	sb.BlockNumber = 14
	bd := BidTraceReceived{
		BidTrace:    sb.BidTrace,
		Timestamp:   sb.Timestamp.UTC().Unix(),
		TimestampMs: sb.Timestamp.UTC().UnixMilli(),
	}
	su, err = store.BlockSubmissionsPayload(BuilderBlockQuery{Slot: 14, Limit: 100})
	require.NoError(t, err)
	require.Equal(t, []BidTraceReceived{bd}, su)

	keys := make([]string, 0)
	err = bolted.SugaredRead(store.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(payloadExecutedMapPth); !it.IsDone(); it.Next() {
			keys = append(keys, it.GetKey())
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 9, len(keys))

	skeys := make([]string, 0)
	hkeys := make([]string, 0)
	nkeys := make([]string, 0)
	err = bolted.SugaredRead(store.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(payloadSubmissionsBlockHashMapPth); !it.IsDone(); it.Next() {
			hkeys = append(hkeys, it.GetKey())
		}
		for it := tx.Iterator(payloadSubmissionsBlockNumberMapPth); !it.IsDone(); it.Next() {
			nkeys = append(nkeys, it.GetKey())
		}
		for it := tx.Iterator(payloadSubmissionsSlotMapPth); !it.IsDone(); it.Next() {
			skeys = append(skeys, it.GetKey())
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 9, len(hkeys))
	require.Equal(t, 9, len(nkeys))
	require.Equal(t, 9, len(skeys))
}
