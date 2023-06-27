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
	"encoding/json"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/draganm/bolted"
	"github.com/draganm/bolted/dbpath"
	"github.com/draganm/bolted/embedded"
	"github.com/manifoldfinance/mev-freelay/logger"
	"go.etcd.io/bbolt"
)

var (
	blockBuilderMapPth                = dbpath.ToPath("block_builder") // block builder
	validatorMapPth                   = dbpath.ToPath("validator")
	payloadDeliveredBlockHashMapPth   = dbpath.ToPath("payload_delivered_block_hash")   // delivered payloads - holds delivered payload
	payloadSubmissionsBlockHashMapPth = dbpath.ToPath("payload_submissions_block_hash") // payload submissions - block builder submissions - holds submission payload
	payloadMissedMapPth               = dbpath.ToPath("payload_missed")                 // delivered payloads - holds delivered payload
	payloadExecutedMapPth             = dbpath.ToPath("payload_executed")               // executed payloads
	bidTraceMapPth                    = dbpath.ToPath("bid_trace")                      // bid trace - block builder submissions
)

type bboltDB struct {
	db bolted.Database
}

func NewBBoltDB(pth string) (*bboltDB, error) {
	db, err := createBBoltDB(pth, []dbpath.Path{})
	if err != nil {
		logger.Error(err, "failed to create bbolt db")
		return nil, err
	}

	return &bboltDB{db: db}, nil
}

func (s *bboltDB) Close() {
	if err := s.db.Close(); err != nil {
		logger.Error(err, "failed to close store")
	}
}

func (s *bboltDB) WriteBuildersToPebbleDB(pDB *pebbleDB) error {
	return bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		batch := pDB.db.NewBatch()
		defer batch.Close() // nolint: errcheck

		for it := tx.Iterator(blockBuilderMapPth); !it.IsDone(); it.Next() {
			key := pDB.key(builderDBKey, it.GetKey())
			if err := batch.Set(key, it.GetValue(), pebble.Sync); err != nil {
				return err
			}
		}

		return batch.Commit(pebble.Sync)
	})
}

func (s *bboltDB) WriteValidatorsToPebbleDB(pDB *pebbleDB) error {
	return bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		batch := pDB.db.NewBatch()
		defer batch.Close() // nolint: errcheck
		for it := tx.Iterator(validatorMapPth); !it.IsDone(); it.Next() {
			key := pDB.key(validatorDBKey, it.GetKey())
			if err := batch.Set(key, it.GetValue(), pebble.Sync); err != nil {
				return err
			}
		}
		return batch.Commit(pebble.Sync)
	})
}

func (s *bboltDB) WriteDeliveredToPebbleDB(pDB *pebbleDB) error {
	return bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(payloadDeliveredBlockHashMapPth); !it.IsDone(); it.Next() {
			var payload DeliveredPayload
			if err := json.Unmarshal(it.GetValue(), &payload); err != nil {
				return err
			}

			if err := pDB.PutDelivered(payload); err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *bboltDB) WriteSubmittedToPebbleDB(pDB *pebbleDB) error {
	return bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(payloadSubmissionsBlockHashMapPth); !it.IsDone(); it.Next() {
			var payload BidTraceExtended
			if err := json.Unmarshal(it.GetValue(), &payload); err != nil {
				return err
			}

			if err := pDB.PutSubmitted(payload); err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *bboltDB) WriteMissedToPebbleDB(pDB *pebbleDB) error {
	return bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		for it := tx.Iterator(payloadMissedMapPth); !it.IsDone(); it.Next() {
			var payload MissedPayload
			if err := json.Unmarshal(it.GetValue(), &payload); err != nil {
				return err
			}

			if err := pDB.PutMissed(payload); err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *bboltDB) WriteExecutedToPebbleDB(pDB *pebbleDB) error {
	return bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		batch := pDB.db.NewBatch()
		defer batch.Close() // nolint: errcheck
		for it := tx.Iterator(payloadExecutedMapPth); !it.IsDone(); it.Next() {
			key := pDB.key(executedDBKey, it.GetKey())
			if err := batch.Set(key, it.GetValue(), pebble.Sync); err != nil {
				return err
			}
		}

		for it := tx.Iterator(bidTraceMapPth); !it.IsDone(); it.Next() {
			key := pDB.key(bidTraceDBKey, it.GetKey())
			if err := batch.Set(key, it.GetValue(), pebble.Sync); err != nil {
				return err
			}
		}

		return batch.Commit(pebble.Sync)
	})
}

func (s *bboltDB) WriteBidTraceToPebbleDB(pDB *pebbleDB) error {
	return bolted.SugaredRead(s.db, func(tx bolted.SugaredReadTx) error {
		batch := pDB.db.NewBatch()
		defer batch.Close() // nolint: errcheck
		for it := tx.Iterator(bidTraceMapPth); !it.IsDone(); it.Next() {
			key := pDB.key(bidTraceDBKey, it.GetKey())
			if err := batch.Set(key, it.GetValue(), pebble.Sync); err != nil {
				return err
			}
		}

		return batch.Commit(pebble.Sync)
	})
}

func createBBoltDB(pth string, mapPths []dbpath.Path) (bolted.Database, error) {
	db, err := connectBBoltDB(pth)
	if err != nil {
		return nil, err
	}

	if err := bolted.SugaredWrite(db, func(tx bolted.SugaredWriteTx) error {
		for _, pth := range mapPths {
			if !tx.Exists(pth) {
				tx.CreateMap(pth)
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return db, nil
}

func connectBBoltDB(filepath string) (bolted.Database, error) {
	db, err := embedded.Open(
		filepath,
		0700,
		embedded.Options{
			Options: bbolt.Options{
				Timeout:      1 * time.Second,
				FreelistType: bbolt.FreelistMapType,
				PageSize:     8192,
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return db, nil
}
