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
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func Restore() *cli.Command {
	return &cli.Command{
		Name:  "restore",
		Usage: `restore database from s3 backup`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
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
			&cli.StringFlag{
				Name:    "db-pth",
				Value:   "dsb/prod_db",
				EnvVars: []string{"DB_PTH"},
			},
		},
		Action: func(c *cli.Context) error {
			defer zap.L().Sync() // nolint:errcheck
			logger.SetVersion(c.String("sha-version"))

			log := logger.WithValues("cmd", "restore")

			_, err := os.Stat(c.String("db-pth"))
			if err == nil {
				log.Error(err, "db already exists, skipping restore")
				return nil
			}

			ctx, cancel := context.WithCancel(c.Context)
			defer cancel()

			cfg, err := config.LoadDefaultConfig(ctx)
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
					ctx,
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
				Prefix: aws.String(restorePrefix),
			})
			if err != nil {
				return fmt.Errorf("list objects: %w", err)
			}

			// filter the objects to only those that match the regex
			var matchingKeys []types.Object
			for _, obj := range resp.Contents {
				if restoreRgx.MatchString(*obj.Key) {
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

			logger.Info("extracting backup", "dir", c.String("db-pth"), "file", *key)
			gr, err := gzip.NewReader(res.Body)
			if err != nil {
				logger.Error(err, "gzip new reader")
				return err
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

				pth := filepath.Join(c.String("db-pth"), header.Name)
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

			logger.Info("backup extracted", "dir", c.String("db-pth"))

			return nil
		},
	}
}
