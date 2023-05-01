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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	relay "github.com/manifoldfinance/mev-freelay/freelay"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	ErrDBDirNotEmpty = errors.New("db-dir is not empty")
)

func main() {
	app := &cli.App{
		Usage: "migrate db to the newer version",
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
		},
		Action: func(c *cli.Context) error {
			defer zap.L().Sync() // nolint:errcheck
			logger.SetVersion(c.String("sha-version"))
			prefix := filepath.Join(c.String("db-dir"), c.String("db-prefix"))

			if err := filepath.Walk(c.String("db-dir"), func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if !info.IsDir() && strings.HasPrefix(info.Name(), fmt.Sprintf("%s.", c.String("db-prefix"))) {
					return ErrDBDirNotEmpty
				}

				return nil
			}); err != nil && os.IsNotExist(err) || err == nil {
				if err == nil {
					return os.ErrNotExist
				}
				logger.Error(err, "walk through db is empty")
				return err
			}

			logger.Info("starting migration db", "prefix", prefix)
			if err := relay.Migrate(prefix); err != nil {
				logger.Error(err, "failed to migrate")
				return err
			}

			logger.Info("finished migrating db", "prefix", prefix)

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		if os.IsNotExist(err) {
			logger.Info("db-dir is empty, skipping migrate")
			os.Exit(0)
		}
		logger.Error(err, "run")
		os.Exit(1)
	}
}
