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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/draganm/bolted"
	"github.com/draganm/bolted/dbpath"
	"github.com/manifoldfinance/mev-freelay/logger"
	"go.etcd.io/bbolt"
)

var (
	byteToMB            int64 = 1048576
	versionMapPth             = dbpath.ToPath("version")
	versionKey                = "db_version"
	importSqlVersionKey       = "import_sql_version"
)

func Migrate(prefix string) error {
	version, err := currentVersion(prefix)
	if err != nil {
		return err
	}

	logger.Info("current database version", "version", version)

	return nil
}

func currentVersion(prefix string) (uint64, error) {
	var version uint64
	sPth := joinDBPth(prefix, storeDBPth)
	sDB, err := connectStore(sPth)
	if err != nil {
		return 0, err
	}
	defer sDB.Close() // nolint:errcheck

	if err := bolted.SugaredRead(sDB, func(tx bolted.SugaredReadTx) error {
		key := versionMapPth.Append(versionKey)
		if !tx.Exists(key) {
			return nil
		}
		version = byteArrayToInt[uint64](tx.Get(key))

		return nil
	}); err != nil {
		return 0, err
	}

	return version, nil
}

func ImportSqlVersion(prefix string) (uint64, error) {
	var version uint64
	sPth := joinDBPth(prefix, storeDBPth)
	sDB, err := connectStore(sPth)
	if err != nil {
		return 0, err
	}
	defer sDB.Close() // nolint:errcheck

	if err := bolted.SugaredRead(sDB, func(tx bolted.SugaredReadTx) error {
		key := versionMapPth.Append(importSqlVersionKey)
		if !tx.Exists(key) {
			return nil
		}
		version = byteArrayToInt[uint64](tx.Get(key))

		return nil
	}); err != nil {
		return 0, err
	}

	logger.Info("current sql import version", "version", version)

	return version, nil
}

func SetImportSqlVersion(prefix string, v uint64) error {
	curr, err := ImportSqlVersion(prefix)
	if err != nil {
		return err
	}
	if curr >= v {
		logger.Info("dont need to import it is already at the specified version")
		return nil
	}

	sPth := joinDBPth(prefix, storeDBPth)
	sDB, err := connectStore(sPth)
	if err != nil {
		return err
	}
	defer sDB.Close() // nolint:errcheck

	if err := bolted.SugaredWrite(sDB, func(tx bolted.SugaredWriteTx) error {
		key := versionMapPth.Append(importSqlVersionKey)
		tx.Put(key, intToByteArray(v))
		return nil
	}); err != nil {
		return err
	}

	logger.Info("set sql import version", "version", v)
	return nil
}

func CreateBackup(w http.ResponseWriter, tw *tar.Writer, db bolted.Database, dbPrefix, currDBPrefix string) error {
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=backup_%d.tar", time.Now().Unix()))

	pth := joinDBPth(dbPrefix, storeDBPth)
	if err := dumpDB(tw, db, pth); err != nil {
		logger.Error(err, "failed to dump db", "db", pth)
		return err
	}
	return nil
}

func Compact(prefix string) error {
	pth := joinDBPth(prefix, storeDBPth)
	compact, err := checkDBNeedsCompacting(pth)
	if err != nil {
		return err
	}

	if compact {
		tmp := fmt.Sprintf("%s.tmp", pth)
		logger.Info("compacting db", "pth", pth, "tmp", tmp)
		if err := compactDB(pth, tmp); err != nil {
			return err
		}

		logger.Info("replacing current db with tmp", "pth", pth, "tmp", tmp)
		if err := os.Rename(tmp, pth); err != nil {
			return err
		}

		logger.Info("compact done", "pth", pth)
	}

	return nil
}

func Archive(db bolted.Database, tw *tar.Writer, w http.ResponseWriter, slot uint64) error {
	if err := bolted.SugaredRead(db, func(tx bolted.SugaredReadTx) error {
		var (
			findSlot string              = prefixKey(slot)
			slots    map[string]struct{} = make(map[string]struct{})
		)

		w.Header().Set("Content-Type", "application/x-tar")
		if err := writeTarFilename(w, tx, findSlot); err != nil {
			return err
		}

		itSub := tx.Iterator(payloadSubmissionsSlotMapPth)
		itSub.Seek(findSlot)
		if itSub.GetKey() != findSlot {
			itSub.Prev()
		}

		for ; !itSub.IsDone(); itSub.Prev() {
			slotKey := itSub.GetKey()
			for itSubSlot := tx.Iterator(payloadSubmissionsSlotMapPth.Append(slotKey)); !itSubSlot.IsDone(); itSubSlot.Next() {
				blockHash := itSubSlot.GetKey()
				if !tx.Exists(payloadSubmissionsBlockHashMapPth.Append(blockHash)) {
					continue
				}

				b := tx.Get(payloadSubmissionsBlockHashMapPth.Append(blockHash))
				var bid BidTraceExtended
				if err := json.Unmarshal(b, &bid); err != nil {
					return err
				}

				exeParts := strings.Split(bid.ExecutionPayloadKey, "_")
				if len(exeParts) != 3 {
					return fmt.Errorf("invalid execution payload key %s", bid.ExecutionPayloadKey)
				}

				execID := fmt.Sprintf("%018d_%s_%s", bid.Slot, exeParts[1], exeParts[2])

				archive := BidTraceArchived{
					Slot:                 bid.Slot,
					BuilderPubkey:        bid.BuilderPubkey,
					ProposerPubkey:       bid.ProposerPubkey,
					ProposerFeeRecipient: bid.ProposerFeeRecipient,
					Value:                bid.Value,
					Signature:            bid.Signature,
					Timestamp:            bid.Timestamp.UTC().Unix(),
					IP:                   bid.IP,
					SimError:             bid.SimError,
				}

				if tx.Exists(payloadExecutedMapPth.Append(execID)) {
					bExe := tx.Get(payloadExecutedMapPth.Append(execID))
					var exe VersionedExecutedPayload
					if err := json.Unmarshal(bExe, &exe); err != nil {
						return err
					}

					archive.ExecutedPayload = &GetPayloadResponse{
						Capella: exe.Capella,
					}
				}

				if err := writeTar(tw, slotKey, exeParts[1], exeParts[2], archive, bid.Timestamp, slots); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func Prune(db bolted.Database, slot uint64) error {
	return bolted.SugaredWrite(db, func(tx bolted.SugaredWriteTx) error {
		var (
			findSlot          string = prefixKey(slot)
			findSlotPrefix    string = fmt.Sprintf("%s_", findSlot)
			executed                 = make([]string, 0)
			slots                    = make([]string, 0)
			blockNumbers             = make(map[string]struct{}, 0)
			blockHashes              = make([]string, 0)
			bidTraces                = make([]string, 0)
			headerBestBids           = make([]string, 0)
			headerBidBuilders        = make([]string, 0)
		)

		// executed payloads
		itDownExe := tx.Iterator(payloadExecutedMapPth)
		itDownExe.Seek(findSlot)
		if !strings.HasPrefix(itDownExe.GetKey(), findSlotPrefix) {
			itDownExe.Prev()
		} else {
			itUpExe := tx.Iterator(payloadExecutedMapPth)
			itUpExe.Seek(findSlot)
			itUpExe.Next()
			for ; !itUpExe.IsDone(); itUpExe.Next() {
				key := itUpExe.GetKey()
				if !strings.HasPrefix(key, findSlotPrefix) {
					break
				}
				executed = append(executed, key)
			}
		}
		for ; !itDownExe.IsDone(); itDownExe.Prev() {
			executed = append(executed, itDownExe.GetKey())
		}

		// submission payloads
		itSub := tx.Iterator(payloadSubmissionsSlotMapPth)
		itSub.Seek(findSlot)
		if itSub.GetKey() != findSlot {
			itSub.Prev()
		}
		for ; !itSub.IsDone(); itSub.Prev() {
			slotKey := itSub.GetKey()
			slots = append(slots, slotKey)

			for itSlot := tx.Iterator(payloadSubmissionsSlotMapPth.Append(slotKey)); !itSlot.IsDone(); itSlot.Next() {
				blockHash := itSlot.GetKey()
				blockHashes = append(blockHashes, blockHash)

				if tx.Exists(payloadSubmissionsBlockHashMapPth.Append(blockHash)) {
					b := tx.Get(payloadSubmissionsBlockHashMapPth.Append(blockHash))
					var bid BidTraceExtended
					if err := json.Unmarshal(b, &bid); err != nil {
						return err
					}

					blockNumber := prefixKey(bid.BlockNumber)
					if _, ok := blockNumbers[blockNumber]; !ok && tx.Exists(payloadSubmissionsBlockNumberMapPth.Append(blockNumber)) {
						blockNumbers[blockNumber] = struct{}{}
					}
				}
			}
		}

		// bidTrace
		itDownBt := tx.Iterator(bidTraceMapPth)
		itDownBt.Seek(findSlot)
		if !strings.HasPrefix(itDownBt.GetKey(), findSlotPrefix) {
			itDownBt.Prev()
		} else {
			itUpBt := tx.Iterator(bidTraceMapPth)
			itUpBt.Seek(findSlot)
			itUpBt.Next()
			for ; !itUpBt.IsDone(); itUpBt.Next() {
				key := itUpBt.GetKey()
				if !strings.HasPrefix(key, findSlotPrefix) {
					break
				}
				bidTraces = append(bidTraces, key)
			}
		}
		for ; !itDownBt.IsDone(); itDownBt.Prev() {
			bidTraces = append(bidTraces, itDownBt.GetKey())
		}

		// header
		itDownHbb := tx.Iterator(headerBestBidMapPth)
		itDownHbb.Seek(findSlot)
		if !strings.HasPrefix(itDownHbb.GetKey(), findSlotPrefix) {
			itDownHbb.Prev()
		} else {
			itUpHbb := tx.Iterator(headerBestBidMapPth)
			itUpHbb.Seek(findSlot)
			itUpHbb.Next()
			for ; !itUpHbb.IsDone(); itUpHbb.Next() {
				key := itUpHbb.GetKey()
				if !strings.HasPrefix(key, findSlotPrefix) {
					break
				}
				headerBestBids = append(headerBestBids, key)
			}
		}
		for ; !itDownHbb.IsDone(); itDownHbb.Prev() {
			headerBestBids = append(headerBestBids, itDownHbb.GetKey())
		}

		itDownHb := tx.Iterator(headerBidBuilderMapPth)
		itDownHb.Seek(findSlot)
		if !strings.HasPrefix(itDownHb.GetKey(), findSlotPrefix) {
			itDownHb.Prev()
		} else {
			itUpHb := tx.Iterator(headerBidBuilderMapPth)
			itUpHb.Seek(findSlot)
			itUpHb.Next()
			for ; !itUpHb.IsDone(); itUpHb.Next() {
				key := itUpHb.GetKey()
				if !strings.HasPrefix(key, findSlotPrefix) {
					break
				}
				headerBidBuilders = append(headerBidBuilders, key)
			}
		}
		for ; !itDownHb.IsDone(); itDownHb.Prev() {
			headerBidBuilders = append(headerBidBuilders, itDownHb.GetKey())
		}

		// delete all keys that are older than the slot
		for _, key := range headerBidBuilders {
			tx.Delete(headerBidBuilderMapPth.Append(key))
		}

		for _, key := range headerBestBids {
			tx.Delete(headerBestBidMapPth.Append(key))
		}

		for _, key := range bidTraces {
			tx.Delete(bidTraceMapPth.Append(key))
		}

		for _, key := range executed {
			tx.Delete(payloadExecutedMapPth.Append(key))
		}

		for blockNumber := range blockNumbers {
			tx.Delete(payloadSubmissionsBlockNumberMapPth.Append(blockNumber))
		}

		for _, blockHash := range blockHashes {
			tx.Delete(payloadSubmissionsBlockHashMapPth.Append(blockHash))
		}

		for _, slot := range slots {
			tx.Delete(payloadSubmissionsSlotMapPth.Append(slot))
		}
		return nil
	})
}

func writeTarFilename(w http.ResponseWriter, tx bolted.SugaredReadTx, slot string) error {
	it := tx.Iterator(payloadSubmissionsSlotMapPth)
	it.Seek(slot)
	if it.GetKey() != slot {
		it.Prev()
	}
	if it.IsDone() {
		return ErrNoArchivePayloadsFound
	}

	to := it.GetKey()
	it.First()
	from := it.GetKey()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=slot_%s_%s.tar", from, to))

	return nil
}

func writeTar(tw *tar.Writer, slot, proposerPubKey, blockHash string, payload BidTraceArchived, timestamp time.Time, slots map[string]struct{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// create a folder if it doesnt exist
	if _, ok := slots[slot]; !ok {
		slots[slot] = struct{}{}
		if err := tw.WriteHeader(&tar.Header{
			Name:     slot,
			Typeflag: tar.TypeDir,
			Mode:     0755,
			ModTime:  timestamp.UTC(),
		}); err != nil {
			return err
		}
	}

	// write the payload
	if err := tw.WriteHeader(&tar.Header{
		Name:    fmt.Sprintf("%s/%d_%s_%s.json", slot, payload.Timestamp, proposerPubKey, blockHash),
		Mode:    0644,
		Size:    int64(len(body)),
		ModTime: timestamp.UTC(),
	}); err != nil {
		return err
	}
	if _, err := tw.Write(body); err != nil {
		return err
	}

	return nil
}

func checkDBNeedsCompacting(pth string) (bool, error) {
	db, err := bbolt.Open(pth, 0666, nil)
	if err != nil {
		return false, err
	}
	defer db.Close() // nolint:errcheck

	btx, err := db.Begin(false)
	if err != nil {
		return false, err
	}
	defer btx.Rollback() // nolint:errcheck

	size := btx.Size()
	sizeInUse := size - (int64(db.Stats().FreePageN) * int64(db.Info().PageSize))

	logger.Info("checking space", "size", size, "sizeInUse", sizeInUse, "pth", pth)

	space := size / byteToMB
	if space < 50 {
		return false, nil
	}

	spaceInUse := sizeInUse / byteToMB
	if float64((spaceInUse*100)/space) < 50 {
		return true, nil
	}

	return false, nil
}

func compactDB(source, dst string) error {
	s, err := bbolt.Open(
		source,
		0700,
		&bbolt.Options{
			Timeout:  1 * time.Second,
			ReadOnly: true,
		},
	)
	if err != nil {
		return err
	}
	defer s.Close() // nolint:errcheck

	d, err := bbolt.Open(
		dst,
		0700,
		&bbolt.Options{
			Timeout:      1 * time.Second,
			PageSize:     8192,
			FreelistType: bbolt.FreelistMapType,
			NoSync:       true,
		},
	)
	if err != nil {
		return err
	}
	defer d.Close() // nolint:errcheck

	err = bbolt.Compact(d, s, 100000000)
	if err != nil {
		return err
	}

	return nil
}

func dumpDB(tw *tar.Writer, db bolted.Database, pth string) error {
	return bolted.SugaredRead(db, func(tx bolted.SugaredReadTx) error {
		if err := tw.WriteHeader(&tar.Header{
			Name:    pth,
			Mode:    0644,
			Size:    tx.FileSize(),
			ModTime: time.Now().UTC(),
		}); err != nil {
			return err
		}
		logger.Info("dumping db", "db", pth)
		tx.Dump(tw)
		logger.Info("dumped db", "db", pth)
		return nil
	})
}

// nolint:unused
func updateVersion(prefix string, version uint64) error {
	sDB, err := createStore(joinDBPth(prefix, storeDBPth), []dbpath.Path{versionMapPth})
	if err != nil {
		return err
	}
	defer sDB.Close() // nolint:errcheck

	return bolted.SugaredWrite(sDB, func(tx bolted.SugaredWriteTx) error {
		tx.Put(versionMapPth.Append(versionKey), intToByteArray(version))
		return nil
	})
}

// nolint:unused
func createBackup(db bolted.Database, pth string, version uint64) error {
	bak := fmt.Sprintf("%s.%d.bak", pth, version)
	file, err := os.Create(bak)
	if err != nil {
		return err
	}
	defer file.Close() // nolint:errcheck

	return bolted.SugaredRead(db, func(tx bolted.SugaredReadTx) error {
		tx.Dump(file)
		return nil
	})
}
