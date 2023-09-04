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
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/cockroachdb/pebble"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/manifoldfinance/mev-freelay/logger"
)

func ImportSqlDeliveredData(log logger.Logger, db *sqlx.DB, dbPth, table string, limit uint64) error {
	pdb, err := NewPebbleDB(dbPth, true)
	if err != nil {
		log.Error(err, "failed to connect to db")
		return err
	}
	defer pdb.Close()

	exists, err := sqlCheckIfTableExists(db, table)
	if err != nil {
		log.Error(err, "failed to check if table exists", "table", table)
		return err
	}
	if !exists {
		log.Info("table does not exist")
		return nil
	}

	log.Info("table exists and will start fetching delivered data")

	count, err := sqlCountTableItems(db, table)
	if err != nil {
		log.Error(err, "failed to count delivered payloads")
		return err
	}
	log.Info("counted delivered payloads", "count", count)

	if count == 0 {
		log.Info("no delivered payloads to import")
		return nil
	}

	inserted := uint64(0)
	skipped := uint64(0)
	offset := uint64(0)
	for {
		payloads, err := sqlDeliveredPayloads(log, db, table, offset, limit)
		if err != nil {
			log.Error(err, "failed to get delivered payloads")
			return err
		}

		if len(payloads) == 0 {
			break
		}

		for _, payload := range payloads {
			existing, err := pdb.Delivered(ProposerPayloadQuery{
				BlockHash: payload.BlockHash,
				Limit:     1,
			})
			if err != nil && err != pebble.ErrNotFound {
				log.Error(err, "failed to get delivered payload")
				return err
			}
			if len(existing) > 0 {
				// log.Info("skipping delivered payload", "blockHash", payload.BlockHash, "slot", payload.Slot, "proposerPubkey", payload.ProposerPubkey)
				skipped++
				continue
			}

			if err := pdb.PutDelivered(payload); err != nil {
				log.Error(err, "failed to put delivered payload")
				return err
			}

			inserted++
		}

		offset += uint64(len(payloads))
		log.Info("importing delivered payloads", "offset", offset, "limit", limit, "count", len(payloads), "inserted", inserted, "skipped", skipped)
	}

	log.Info("imported delivered payloads", "count", count, "inserted", inserted, "skipped", skipped)
	return nil
}

func ImportSqlBlockBuilderData(log logger.Logger, db *sqlx.DB, dbPth, table string, limit uint64) error {
	pdb, err := NewPebbleDB(dbPth, true)
	if err != nil {
		log.Error(err, "failed to connect to db")
		return err
	}
	defer pdb.Close()

	exists, err := sqlCheckIfTableExists(db, table)
	if err != nil {
		log.Error(err, "failed to check if table exists", "table", table)
		return err
	}
	if !exists {
		log.Info("table does not exist")
		return nil
	}

	log.Info("table exists and will start fetching block builders data")

	count, err := sqlCountTableItems(db, table)
	if err != nil {
		log.Error(err, "failed to count block builders")
		return err
	}
	log.Info("counted block builders", "count", count)

	if count == 0 {
		log.Info("no block builders to import")
		return nil
	}

	inserted := uint64(0)
	skipped := uint64(0)
	offset := uint64(0)
	for {
		payloads, err := sqlBlockBuilders(db, table, offset, limit)
		if err != nil {
			log.Error(err, "failed to get block builders")
			return err
		}

		if len(payloads) == 0 {
			break
		}

		for _, payload := range payloads {
			ok, err := pdb.IsKnownBuilder(payload.BuilderPubkey)
			if ok || (err != nil && err != pebble.ErrNotFound) {
				continue
			}

			if err := pdb.InsertBlockBuilder(payload); err != nil {
				log.Error(err, "failed to put block builder")
				return err
			}

			inserted++
		}

		offset += uint64(len(payloads))

		log.Info("importing block builders", "offset", offset, "limit", limit, "count", len(payloads), "inserted", inserted, "skipped", skipped)
	}

	log.Info("imported block builders", "count", count, "inserted", inserted, "skipped", skipped)
	return nil
}

func sqlDeliveredPayloads(log logger.Logger, db *sqlx.DB, table string, offset, limit uint64) ([]DeliveredPayload, error) {
	if limit > 100 {
		limit = 100
	}
	var rows []sqlDeliveredPayload
	err := db.Select(&rows, "SELECT * FROM "+table+" LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}

	payloads := make([]DeliveredPayload, len(rows))
	for i, row := range rows {
		var parentHash types.Hash
		if err := parentHash.UnmarshalText([]byte(row.ParentHash)); err != nil {
			return nil, err
		}
		var blockHash types.Hash
		if err := blockHash.UnmarshalText([]byte(row.BlockHash)); err != nil {
			return nil, err
		}
		var builderPubkey types.PublicKey
		if err := builderPubkey.UnmarshalText([]byte(row.BuilderPubkey)); err != nil {
			return nil, err
		}
		var proposerPubkey types.PublicKey
		if err := proposerPubkey.UnmarshalText([]byte(row.ProposerPubkey)); err != nil {
			return nil, err
		}
		var proposerFeeRecipient types.Address
		if err := proposerFeeRecipient.UnmarshalText([]byte(row.ProposerFeeRecipient)); err != nil {
			return nil, err
		}
		var value types.U256Str
		if err := value.UnmarshalText([]byte(row.Value)); err != nil {
			return nil, err
		}
		signed := new(SignedBlindedBeaconBlock)
		capellaBlock := new(apicapella.SignedBlindedBeaconBlock)
		signedBody := sqlNullStringToByte(row.SignedBlindedBeaconBlock)
		if err := json.NewDecoder(bytes.NewBuffer(signedBody)).Decode(&capellaBlock); err != nil {
			bellatrixBlock := new(types.SignedBlindedBeaconBlock)
			if err := json.NewDecoder(bytes.NewBuffer(signedBody)).Decode(bellatrixBlock); err != nil {
				log.Error(errors.New("signed blinded beacon block unmarshal error"), "failed to unmarshal bellatrix block and capella block")
				return nil, err
			}
			signed.Bellatrix = bellatrixBlock
		} else {
			signed.Capella = capellaBlock
		}

		payloads[i] = DeliveredPayload{
			BidTrace: BidTrace{
				BlockNumber: row.BlockNumber,
				NumTx:       row.NumTx,
				BidTrace: types.BidTrace{
					Slot:                 row.Slot,
					ParentHash:           parentHash,
					BlockHash:            blockHash,
					BuilderPubkey:        builderPubkey,
					ProposerPubkey:       proposerPubkey,
					ProposerFeeRecipient: proposerFeeRecipient,
					GasLimit:             row.GasLimit,
					GasUsed:              row.GasUsed,
					Value:                value,
				},
			},
			Timestamp:                row.InsertedAt,
			SignedBlindedBeaconBlock: signed,
		}
	}

	return payloads, err
}

func sqlBlockBuilders(db *sqlx.DB, table string, offset, limit uint64) ([]BlockBuilder, error) {
	if limit > 100 {
		limit = 100
	}
	var rows []sqlBlockBuilder
	err := db.Select(&rows, "SELECT * FROM "+table+" LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}

	payloads := make([]BlockBuilder, len(rows))
	for i, row := range rows {
		var builderPubkey types.PublicKey
		if err := builderPubkey.UnmarshalText([]byte(row.BuilderPubkey)); err != nil {
			return nil, err
		}
		payloads[i] = BlockBuilder{
			CreatedAt:               row.InsertedAt,
			UpdatedAt:               row.InsertedAt,
			BuilderPubkey:           builderPubkey,
			Description:             row.Description,
			HighPriority:            row.IsHighPrio,
			Blacklisted:             row.IsBlacklisted,
			LastSubmissionSlot:      row.LastSubmissionSlot,
			NumSubmissionsTotal:     row.NumSubmissionsTotal,
			NumSubmissionsSimFailed: row.NumSubmissionsSimError,
			FirstSubmissionAt:       row.InsertedAt,
		}
	}

	return payloads, err
}

func sqlCheckIfTableExists(db *sqlx.DB, table string) (bool, error) {
	var exists bool
	err := db.Get(&exists, "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table)
	return exists, err
}

func sqlCountTableItems(db *sqlx.DB, table string) (uint64, error) {
	var count uint64
	err := db.Get(&count, "SELECT COUNT(id) FROM "+table)
	return count, err
}

type sqlDeliveredPayload struct {
	ID                       int64          `db:"id"`
	InsertedAt               time.Time      `db:"inserted_at"`
	SignedAt                 sql.NullTime   `db:"signed_at"`
	SignedBlindedBeaconBlock sql.NullString `db:"signed_blinded_beacon_block"`
	Slot                     uint64         `db:"slot"`
	Epoch                    uint64         `db:"epoch"`
	BuilderPubkey            string         `db:"builder_pubkey"`
	ProposerPubkey           string         `db:"proposer_pubkey"`
	ProposerFeeRecipient     string         `db:"proposer_fee_recipient"`
	ParentHash               string         `db:"parent_hash"`
	BlockHash                string         `db:"block_hash"`
	BlockNumber              uint64         `db:"block_number"`
	GasUsed                  uint64         `db:"gas_used"`
	GasLimit                 uint64         `db:"gas_limit"`
	NumTx                    uint64         `db:"num_tx"`
	Value                    string         `db:"value"`
	PublishMs                uint64         `db:"publish_ms"`
	ExecutionPayloadId       sql.NullString `db:"execution_payload_id"`
}

type sqlBlockBuilder struct {
	ID                     int64         `db:"id"          json:"id"`
	BuilderPubkey          string        `db:"builder_pubkey" json:"builder_pubkey"`
	Description            string        `db:"description"    json:"description"`
	IsHighPrio             bool          `db:"is_high_prio"   json:"is_high_prio"`
	IsBlacklisted          bool          `db:"is_blacklisted" json:"is_blacklisted"`
	IsOptimistic           bool          `db:"is_optimistic"  json:"is_optimistic"`
	Collateral             string        `db:"collateral" json:"collateral"`
	BuilderID              string        `db:"builder_id" json:"builder_id"`
	LastSubmissionID       sql.NullInt64 `db:"last_submission_id"   json:"last_submission_id"`
	LastSubmissionSlot     uint64        `db:"last_submission_slot" json:"last_submission_slot"`
	NumSubmissionsTotal    uint64        `db:"num_submissions_total"    json:"num_submissions_total"`
	NumSubmissionsSimError uint64        `db:"num_submissions_simerror" json:"num_submissions_simerror"`
	NumSentGetPayload      uint64        `db:"num_sent_getpayload" json:"num_sent_getpayload"`
	InsertedAt             time.Time     `db:"inserted_at" json:"inserted_at"`
}

func sqlNullStringToByte(s sql.NullString) []byte {
	if !s.Valid {
		return nil
	}
	return []byte(s.String)
}

// func hidePasswordAndUsernameFromSqlURI(uri string) string {
// 	params := strings.Split(uri, " ")

// 	for i, param := range params {
// 		if strings.HasPrefix(param, "user=") {
// 			params[i] = "user=REDACTED"
// 		} else if strings.HasPrefix(param, "password=") {
// 			params[i] = "password=REDACTED"
// 		}
// 	}

// 	result := strings.Join(params, " ")

// 	return result
// }
