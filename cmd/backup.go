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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func Backup() *cli.Command {
	return &cli.Command{
		Name:  "backup",
		Usage: `backup db to s3`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
			},
			&cli.StringFlag{
				Name:     "backup-url",
				EnvVars:  []string{"BACKUP_URL"},
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

			log := logger.WithValues("cmd", "backup")

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

			sess := s3.NewFromConfig(cfg)
			uploader := manager.NewUploader(sess)

			log.Info("creating backup", "url", c.String("backup-url"))
			req, err := http.NewRequestWithContext(ctx, "GET", c.String("backup-url"), nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close() // nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("backup unexpected status code: %d", resp.StatusCode)
			}

			cd := resp.Header.Get("Content-Disposition")
			if cd == "" {
				return errors.New("no content-disposition")
			}
			filename := strings.TrimPrefix(cd, "attachment; filename=")
			log.Info("filename", "name", filename)

			r, w := io.Pipe()
			defer r.Close() // nolint:errcheck

			gz := gzip.NewWriter(w)

			go func() {
				// we need to close it in this order otherwise we get EOF error when extracting
				defer w.Close()  // nolint:errcheck
				defer gz.Close() // nolint:errcheck
				_, err := io.Copy(gz, resp.Body)
				if err != nil {
					log.Error(err, "write")
					cancel()
				}
			}()

			log.Info("uploading", "filename", filename)
			result, err := uploader.Upload(ctx, &s3.PutObjectInput{
				Bucket: aws.String(c.String("bucket")),
				Key:    aws.String(fmt.Sprintf("%s.gz", filename)),
				Body:   r,
			})
			if err != nil {
				return err
			}
			log.Info("uploaded to", "location", result.Location)

			return nil
		},
	}
}
