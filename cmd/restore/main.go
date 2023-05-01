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
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	ErrDBDirNotEmpty = errors.New("db-dir is not empty")
	ErrNoBackupFound = errors.New("no backup found")
	rgx              = regexp.MustCompile(`backup_(\d+).tar.gz`)
	prefix           = "backup_"
)

func main() {
	app := &cli.App{
		Usage: "restore a database from a backup located in an s3 bucket",
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
				Name:     "bucket",
				EnvVars:  []string{"BUCKET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "aws-uri",
				EnvVars: []string{"AWS_URI"},
			},
		},
		Action: func(c *cli.Context) error {
			defer zap.L().Sync() // nolint:errcheck
			logger.SetVersion(c.String("sha-version"))

			if err := filepath.Walk(c.String("db-dir"), func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if !info.IsDir() && strings.HasPrefix(info.Name(), fmt.Sprintf("%s.", c.String("db-prefix"))) {
					return ErrDBDirNotEmpty
				}

				return nil
			}); err != nil && !os.IsNotExist(err) {
				return err
			}

			err := os.MkdirAll(c.String("db-dir"), 0755)
			if err != nil {
				return err
			}

			cfg, err := config.LoadDefaultConfig(c.Context)
			if err != nil {
				return err
			}

			if c.IsSet("aws-uri") {
				resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{
						PartitionID:       "aws",
						URL:               c.String("aws-uri"),
						HostnameImmutable: true,
					}, nil
				})

				cfg, err = config.LoadDefaultConfig(
					c.Context,
					config.WithEndpointResolverWithOptions(resolver),
				)
				if err != nil {
					return err
				}
			}

			bucket := c.String("bucket")
			sess := s3.NewFromConfig(cfg)

			logger.Info("listing objects in bucket", "bucket", bucket)
			resp, err := sess.ListObjectsV2(c.Context, &s3.ListObjectsV2Input{
				Bucket: aws.String(bucket),
				Prefix: aws.String(prefix),
			})
			if err != nil {
				return fmt.Errorf("list objects: %w", err)
			}

			// filter the objects to only those that match the regex
			var matchingKeys []types.Object
			for _, obj := range resp.Contents {
				if rgx.MatchString(*obj.Key) {
					matchingKeys = append(matchingKeys, obj)
				}
			}

			// sort the matching objects by modification time (newest first)
			sort.Slice(matchingKeys, func(i, j int) bool {
				return matchingKeys[i].LastModified.After(*matchingKeys[j].LastModified)
			})

			if len(matchingKeys) == 0 {
				return ErrNoBackupFound
			}

			key := matchingKeys[0].Key
			logger.Info("found backups", "count", len(matchingKeys))
			logger.Info("latest backup", "key", *key)

			logger.Info("downloading backup", "key", *key)
			res, err := sess.GetObject(c.Context, &s3.GetObjectInput{
				Bucket: aws.String(bucket),
				Key:    key,
			})
			if err != nil {
				return fmt.Errorf("get object: %w", err)
			}
			defer res.Body.Close() // nolint:errcheck

			logger.Info("extracting backup", "dir", c.String("db-dir"), "file", *key)
			gr, err := gzip.NewReader(res.Body)
			if err != nil {
				panic(err)
			}
			defer gr.Close() // nolint:errcheck

			tr := tar.NewReader(gr)
			for {
				header, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}

				pth := filepath.Join(c.String("db-dir"), header.Name)
				if header.Typeflag == tar.TypeDir {
					err := os.MkdirAll(pth, 0755)
					if err != nil {
						return err
					}
					continue
				}

				logger.Info("extracting file", "file", pth)
				file, err := os.OpenFile(pth, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, header.FileInfo().Mode())
				if err != nil {
					return err
				}
				defer file.Close() // nolint:errcheck

				if _, err := io.Copy(file, tr); err != nil {
					return err
				}
			}

			logger.Info("backup extracted", "dir", c.String("db-dir"))

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		if err == ErrDBDirNotEmpty {
			logger.Info("db-dir is not empty, skipping restore")
			os.Exit(0)
		}
		if err == ErrNoBackupFound {
			logger.Info("no backups found, skipping restore")
			os.Exit(0)
		}
		logger.Error(err, "run")
		os.Exit(1)
	}
}
