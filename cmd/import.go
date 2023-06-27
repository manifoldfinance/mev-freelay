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
package cmd

import (
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	relay "github.com/manifoldfinance/mev-freelay/freelay"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func Import() *cli.Command {
	return &cli.Command{
		Name:  "import",
		Usage: "import postgres data (delivered, builders)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
			},
			&cli.StringFlag{
				Name:     "sql-uri",
				EnvVars:  []string{"SQL_URI"},
				Required: true,
			},
			&cli.Uint64Flag{
				Name:    "sql-limit",
				Value:   100,
				EnvVars: []string{"SQL_LIMIT"},
			},
			&cli.StringFlag{
				Name:    "sql-table-prefix",
				Value:   "dev",
				EnvVars: []string{"SQL_TABLE_PREFIX"},
			},
			&cli.StringFlag{
				Name:    "db-pth",
				Value:   "dsb/prod_db",
				EnvVars: []string{"DB_PTH"},
			},
			&cli.BoolFlag{
				Name:    "insert",
				Value:   false,
				EnvVars: []string{"INSERT"},
				Usage:   "it still inserts if db exists but it will not overwrite existing data",
			},
		},
		Action: func(c *cli.Context) error {
			defer zap.L().Sync() // nolint:errcheck
			logger.SetVersion(c.String("sha-version"))

			log := logger.WithValues("cmd", "import")

			_, err := os.Stat(c.String("db-pth"))
			if err == nil && !c.Bool("insert") {
				log.Error(err, "db already exists, skipping import")
				return nil
			}

			uri := c.String("sql-uri")
			sqlTablePrefix := c.String("sql-table-prefix")
			limit := c.Uint64("sql-limit")
			dbPth := c.String("db-pth")

			db, err := sqlx.Connect("postgres", uri)
			if err != nil {
				logger.Error(err, "failed to connect to postgres")
				return err
			}
			defer db.Close() // nolint:errcheck

			db.DB.SetMaxOpenConns(30)
			db.DB.SetMaxIdleConns(10)
			db.DB.SetConnMaxIdleTime(0)

			blockBuilderTable := sqlTablePrefix + "_blockbuilder"
			if err := relay.ImportSqlBlockBuilderData(log, db, dbPth, blockBuilderTable, limit); err != nil {
				log.Error(err, "failed to import block builders sql data")
				return err
			}

			deliveredPayloadsTable := sqlTablePrefix + "_payload_delivered"
			if err := relay.ImportSqlDeliveredData(log, db, dbPth, deliveredPayloadsTable, limit); err != nil {
				log.Error(err, "failed to import delivered payloads sql data")
				return err
			}

			return nil
		},
	}
}
