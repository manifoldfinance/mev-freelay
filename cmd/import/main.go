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
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	relay "github.com/manifoldfinance/mev-freelay/freelay"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func main() {
	app := &cli.App{
		Usage: "import delivered payloads from postgres into bolted",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
			},
			&cli.StringFlag{
				Name:     "db-dir",
				Value:    "dbs",
				EnvVars:  []string{"DB_DIR"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "db-prefix",
				Value:    "prod",
				EnvVars:  []string{"DB_PREFIX"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "sql-uri",
				EnvVars:  []string{"SQL_URI"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "sql-table",
				EnvVars:  []string{"SQL_TABLE"},
				Required: true,
			},
			&cli.Uint64Flag{
				Name:    "sql-limit",
				Value:   100,
				EnvVars: []string{"SQL_LIMIT"},
			},
		},
		Action: func(c *cli.Context) error {
			defer zap.L().Sync() // nolint:errcheck
			logger.SetVersion(c.String("sha-version"))

			var sqlVersion uint64 = 2
			dir := c.String("db-dir")
			prefix := c.String("db-prefix")
			dbPrefix := filepath.Join(c.String("db-dir"), c.String("db-prefix"))

			currSqlVersion, err := relay.ImportSqlVersion(dbPrefix)
			if err != nil {
				logger.Error(err, "failed to import sql version", "dbPrefix", dbPrefix)
				return nil
			}

			if currSqlVersion >= sqlVersion {
				logger.Info("sql version already imported", "sqlVersion", sqlVersion, "dbPrefix", dbPrefix)
				return nil
			}

			uri := c.String("sql-uri")
			table := c.String("sql-table")
			limit := c.Uint64("sql-limit")
			redacted := hideCredentialsFromURL(uri)
			redacted = hidePasswordAndUsernameFromSqlURI(redacted)

			logger.Info("importing postgres delivered payload into bolted", "boltedDir", dir, "boltedPrefix", prefix, "sqlUri", redacted, "sqlTable", table, "sqlVersion", sqlVersion)

			if err := importSqlData(dir, prefix, uri, table, limit); err != nil {
				logger.Error(err, "failed to import sql data")
				return nil
			}

			if err := relay.SetImportSqlVersion(dbPrefix, sqlVersion); err != nil {
				logger.Error(err, "failed setting sql import version")
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Error(err, "run")
		os.Exit(1)
	}
}

func importSqlData(dir, prefix, uri, table string, limit uint64) error {
	storePrefix := filepath.Join(dir, prefix)
	store, err := relay.NewStore(storePrefix)
	if err != nil {
		logger.Error(err, "failed to connect to store")
		return err
	}
	defer store.Close()

	db, err := sqlx.Connect("postgres", uri)
	if err != nil {
		logger.Error(err, "failed to connect to postgres")
		return err
	}
	defer db.Close() // nolint:errcheck

	db.DB.SetMaxOpenConns(30)
	db.DB.SetMaxIdleConns(10)
	db.DB.SetConnMaxIdleTime(0)

	exists, err := checkIfTableExists(db, table)
	if err != nil {
		logger.Error(err, "failed to check if table exists", "table", table)
		return err
	}
	if !exists {
		logger.Info("table does not exist")
		return nil
	}

	logger.Info("table exists and will start fetching delivered data")

	count, err := countDeliveredPayloads(db, table)
	if err != nil {
		logger.Error(err, "failed to count delivered payloads")
		return err
	}
	logger.Info("counted delivered payloads", "count", count)

	if count == 0 {
		logger.Info("no delivered payloads to import")
		return nil
	}

	inserted := uint64(0)
	skipped := uint64(0)
	for offset := uint64(0); offset < count; offset += limit {
		payloads, err := deliveredPayloads(db, table, offset, limit)
		if err != nil {
			logger.Error(err, "failed to get delivered payloads")
			return err
		}

		for _, payload := range payloads {
			existing, err := store.DeliveredPayloads(relay.ProposerPayloadQuery{
				BlockHash: payload.BlockHash,
				Limit:     1,
			})
			if err != nil {
				logger.Error(err, "failed to get delivered payload")
				return err
			}
			if len(existing) > 0 {
				// logger.Info("skipping delivered payload", "blockHash", payload.BlockHash, "slot", payload.Slot, "proposerPubkey", payload.ProposerPubkey)
				skipped++
				continue
			}

			if err := store.PutDeliveredPayload(payload); err != nil {
				logger.Error(err, "failed to put delivered payload")
				return err
			}
			if err := store.UpsertBlockBuilderDeliveredPayload(
				payload.BuilderPubkey,
				payload.Slot,
				payloadID(payload.BlockHash.String(), payload.Slot, payload.ProposerPubkey.String()),
			); err != nil {
				logger.Error(err, "failed to upsert block builder delivered payload")
				return err
			}
			inserted++
		}

		logger.Info("importing delivered payloads", "offset", offset, "limit", limit, "count", len(payloads))
	}

	logger.Info("imported delivered payloads", "count", count, "inserted", inserted, "skipped", skipped)
	return nil
}

func hideCredentialsFromURL(url string) string {
	regex := regexp.MustCompile(`^(.*:\/\/)([^:]+:[^@]+@)(.*)$`)

	placeholder := "$1<redacted>@$3"
	result := regex.ReplaceAllString(url, placeholder)

	return result
}

func hidePasswordAndUsernameFromSqlURI(uri string) string {
	params := strings.Split(uri, " ")

	for i, param := range params {
		if strings.HasPrefix(param, "user=") {
			params[i] = "user=REDACTED"
		} else if strings.HasPrefix(param, "password=") {
			params[i] = "password=REDACTED"
		}
	}

	result := strings.Join(params, " ")

	return result
}

func deliveredPayloads(db *sqlx.DB, table string, offset, limit uint64) ([]relay.DeliveredPayload, error) {
	if limit > 100 {
		limit = 100
	}
	var rows []sqlDeliveredPayload
	err := db.Select(&rows, "SELECT * FROM "+table+" LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}

	payloads := make([]relay.DeliveredPayload, len(rows))
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
		signed := new(relay.SignedBlindedBeaconBlock)
		capellaBlock := new(apicapella.SignedBlindedBeaconBlock)
		signedBody := sqlNullStringToByte(row.SignedBlindedBeaconBlock)
		if err := json.NewDecoder(bytes.NewBuffer(signedBody)).Decode(&capellaBlock); err != nil {
			bellatrixBlock := new(types.SignedBlindedBeaconBlock)
			if err := json.NewDecoder(bytes.NewBuffer(signedBody)).Decode(bellatrixBlock); err != nil {
				logger.Error(errors.New("signed blinded beacon block unmarshal error"), "failed to unmarshal bellatrix block and capella block")
				return nil, err
			}
			signed.Bellatrix = bellatrixBlock
		} else {
			signed.Capella = capellaBlock
		}

		payloads[i] = relay.DeliveredPayload{
			BidTrace: relay.BidTrace{
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

func checkIfTableExists(db *sqlx.DB, table string) (bool, error) {
	var exists bool
	err := db.Get(&exists, "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table)
	return exists, err
}

func countDeliveredPayloads(db *sqlx.DB, table string) (uint64, error) {
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

func sqlNullStringToByte(s sql.NullString) []byte {
	if !s.Valid {
		return nil
	}
	return []byte(s.String)
}

func payloadID(blockHash string, slot uint64, proposerPubkey string) string {
	return fmt.Sprintf("%s/%d_%s", blockHash, slot, proposerPubkey)
}
