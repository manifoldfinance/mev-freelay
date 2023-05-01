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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	ErrNoContent = errors.New("no content")
	rgx          = regexp.MustCompile(`slot_(\d+)_(\d+)`)
)

func main() {
	app := &cli.App{
		Usage: "create a new archive.tar.gz of bidtraces, upload it to s3 and remove the entries from the db",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "archive-url",
				EnvVars:  []string{"ARCHIVE_URL"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "prune-url",
				EnvVars:  []string{"PRUNE_URL"},
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
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
			},
		},
		Action: func(c *cli.Context) error {
			defer zap.L().Sync() // nolint:errcheck
			logger.SetVersion(c.String("sha-version"))

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

			req, err := http.NewRequestWithContext(ctx, "GET", c.String("archive-url"), nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close() // nolint:errcheck

			if resp.StatusCode == http.StatusNoContent {
				return ErrNoContent
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("archive bad status: %s", resp.Status)
			}

			cd := resp.Header.Get("Content-Disposition")
			if cd == "" {
				return errors.New("no content-disposition")
			}
			filename := strings.TrimPrefix(cd, "attachment; filename=")
			logger.Info("filename", "name", filename)

			r, w := io.Pipe()
			defer r.Close() // nolint:errcheck

			gz := gzip.NewWriter(w)

			go func() {
				// we need to close it in this order otherwise we get EOF error when extracting
				defer w.Close()  // nolint:errcheck
				defer gz.Close() // nolint:errcheck
				_, err := io.Copy(gz, resp.Body)
				if err != nil {
					logger.Error(err, "write")
					cancel()
				}
			}()

			logger.Info("uploading", "filename", filename)
			result, err := uploader.Upload(ctx, &s3.PutObjectInput{
				Bucket: aws.String(c.String("bucket")),
				Key:    aws.String(fmt.Sprintf("%s.gz", filename)),
				Body:   r,
			})
			if err != nil {
				return err
			}
			logger.Info("uploaded to", "location", result.Location)

			match := rgx.FindStringSubmatch(filename)
			if len(match) != 3 {
				return fmt.Errorf("invalid filename: %s", filename)
			}

			slot, err := strconv.ParseInt(match[2], 10, 64)
			if err != nil {
				return err
			}

			pruneURI, err := url.JoinPath(c.String("prune-url"), fmt.Sprintf("%d", slot))
			if err != nil {
				logger.Error(err, "error joining path", "uri", c.String("prune-uri"), "slot", slot)
				return err
			}

			logger.Info("pruning", "url", pruneURI)

			reqPrune, err := http.NewRequestWithContext(ctx, "DELETE", pruneURI, nil)
			if err != nil {
				logger.Error(err, "error creating request", "uri", pruneURI)
				return err
			}

			respPrune, err := http.DefaultClient.Do(reqPrune)
			if err != nil {
				logger.Error(err, "error sending request", "uri", pruneURI)
				return err
			}
			defer respPrune.Body.Close() // nolint:errcheck

			if respPrune.StatusCode != http.StatusOK {
				logger.Info("prune bad status", "url", pruneURI, "status", respPrune.Status, "body", respPrune.Body)
				return fmt.Errorf("prune bad status: %s", respPrune.Status)
			}

			logger.Info("pruned", "url", pruneURI, "status", respPrune.Status)

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		if err == ErrNoContent {
			logger.Info("nothing to purge")
			os.Exit(0)
			return
		}
		logger.Error(err, "run")
		os.Exit(1)
	}
}
