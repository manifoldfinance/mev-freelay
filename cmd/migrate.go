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

	"github.com/manifoldfinance/mev-freelay/freelay"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
)

func Migrate() *cli.Command {
	return &cli.Command{
		Name:  "migrate",
		Usage: `migrate from bbolt to pebble`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
			},
			&cli.StringFlag{
				Name:     "bbolt-pth",
				Value:    "dbs/prod.store.db",
				EnvVars:  []string{"BBOLT_PTH"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "pebble-pth",
				Value:   "dsb/prod_db",
				EnvVars: []string{"PEBBLE_PTH"},
			},
		},
		Action: func(c *cli.Context) error {
			logger.SetVersion(c.String("sha-version"))

			log := logger.WithValues("cmd", "migrate")

			_, err := os.Stat(c.String("bbolt-pth"))
			if err != nil {
				log.Error(err, "failed to stat bbolt file, skipping migration")
				return nil
			}

			_, err = os.Stat(c.String("pebble-pth"))
			if err == nil {
				log.Error(err, "pebble db already exists, skipping migration")
				return nil
			}

			bdb, err := freelay.NewBBoltDB(c.String("bbolt-pth"))
			if err != nil {
				log.Error(err, "failed to open bbolt db")
				return err
			}
			defer bdb.Close()

			pdb, err := freelay.NewPebbleDB(c.String("pebble-pth"), true)
			if err != nil {
				log.Error(err, "failed to open pebble db")
				return err
			}
			defer pdb.Close()

			if err := bdb.WriteBuildersToPebbleDB(pdb); err != nil {
				log.Error(err, "failed to write builders to pebble db")
				return err
			}

			if err := bdb.WriteValidatorsToPebbleDB(pdb); err != nil {
				log.Error(err, "failed to write validators to pebble db")
				return err
			}

			if err := bdb.WriteDeliveredToPebbleDB(pdb); err != nil {
				log.Error(err, "failed to write delivered to pebble db")
				return err
			}

			if err := bdb.WriteSubmittedToPebbleDB(pdb); err != nil {
				log.Error(err, "failed to write submitted to pebble db")
				return err
			}

			if err := bdb.WriteMissedToPebbleDB(pdb); err != nil {
				log.Error(err, "failed to write missed to pebble db")
				return err
			}

			if err := bdb.WriteExecutedToPebbleDB(pdb); err != nil {
				log.Error(err, "failed to write executed to pebble db")
				return err
			}

			if err := bdb.WriteBidTraceToPebbleDB(pdb); err != nil {
				log.Error(err, "failed to write bid trace to pebble db")
				return err
			}

			log.Info("migration from bbolt to pebble complete")

			return nil
		},
	}
}
