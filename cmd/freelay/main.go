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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	relay "github.com/manifoldfinance/mev-freelay/freelay"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.uber.org/zap"
)

var (
	ErrNoBeaconsProvided   = errors.New("no beacons provided")
	ErrNoSecretKeyProvided = errors.New("no secret key provided")
)

func main() {
	app := &cli.App{
		Usage: "relay, api, website and sftp services with prometheus",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "addr",
				Value:   ":50051",
				EnvVars: []string{"ADDR"},
			},
			&cli.StringFlag{
				Name:    "network",
				Value:   "main",
				EnvVars: []string{"NETWORK"},
			},
			&cli.StringSliceFlag{
				Name:    "beacons",
				Value:   cli.NewStringSlice("http://localhost:3500"),
				EnvVars: []string{"BEACONS"},
			},
			&cli.StringFlag{
				Name:    "block-sim-url",
				Value:   "http://localhost:8545",
				EnvVars: []string{"BLOCK_SIM_URL"},
			},
			&cli.BoolFlag{
				Name:    "pprof-api",
				Value:   false,
				EnvVars: []string{"PPROF_API"},
			},
			&cli.StringFlag{
				Name:     "secret-key",
				Required: true,
				EnvVars:  []string{"SECRET_KEY"},
			},
			&cli.StringFlag{
				Name:    "db-prefix",
				Value:   "prod",
				EnvVars: []string{"DB_PREFIX"},
			},
			&cli.StringFlag{
				Name:    "db-dir",
				Value:   "dbs",
				EnvVars: []string{"DB_DIR"},
			},
			&cli.StringFlag{
				Name:    "prometheus-addr",
				Value:   ":9000",
				EnvVars: []string{"PROMETHEUS_ADDR"},
			},
			&cli.StringFlag{
				Name:    "api-addr",
				Value:   ":50052",
				EnvVars: []string{"API_ADDR"},
			},
			&cli.StringFlag{
				Name:    "web-addr",
				Value:   ":50053",
				EnvVars: []string{"WEB_ADDR"},
			},
			&cli.StringFlag{
				Name:    "known-validators-pth",
				EnvVars: []string{"KNOWN_VALIDATORS_PTH"},
			},
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
			},
			&cli.StringFlag{
				Name:    "sftp-addr",
				Value:   ":50054",
				EnvVars: []string{"SFTP_ADDR"},
			},
			&cli.BoolFlag{
				Name:    "sftp-db",
				EnvVars: []string{"SFTP_DB"},
				Value:   false,
			},
			&cli.Uint64Flag{
				Name:    "max-rate-limit",
				Value:   60,
				EnvVars: []string{"MAX_RATE_LIMIT"},
			},
			&cli.StringFlag{
				Name:    "events-url",
				EnvVars: []string{"EVENTS_URL"},
			},
			// "Timeout for reading a single request from the client in milliseconds.",
			&cli.Uint64Flag{
				Name:    "read-timeout",
				Value:   1500,
				EnvVars: []string{"READ_TIMEOUT"},
			},
			// "Timeout for reading the headers of a request from the client in milliseconds.",
			&cli.Uint64Flag{
				Name:    "read-head-timeout",
				Value:   600,
				EnvVars: []string{"READ_HEAD_TIMEOUT"},
			},
			// "Timeout for writing a response to the client in seconds.",
			&cli.Uint64Flag{
				Name:    "write-timeout",
				Value:   10,
				EnvVars: []string{"WRITE_TIMEOUT"},
			},
			//"Timeout for an idle connection in seconds.",
			&cli.Uint64Flag{
				Name:    "idle-timeout",
				Value:   3,
				EnvVars: []string{"IDLE_TIMEOUT"},
			},
			// "Timeout on how long to wait for the beacon to propagate the new block over p2p to other nodes in milliseconds.",
			&cli.Uint64Flag{
				Name:    "beacon-propose-timeout",
				Value:   1000,
				EnvVars: []string{"BEACON_PROPOSE_TIMEOUT"},
			},
			&cli.Uint64Flag{
				Name:    "cut-off-timeout",
				Value:   3000,
				EnvVars: []string{"CUT_OFF_TIMEOUT"},
			},
			&cli.BoolFlag{
				Name:    "trace-ip",
				Value:   false,
				EnvVars: []string{"TRACE_IP"},
			},
			&cli.BoolFlag{
				Name:    "allow-builder-cancellations",
				Value:   false,
				EnvVars: []string{"ALLOW_BUILDER_CANCELLATIONS"},
			},
			&cli.Uint64Flag{
				Name:    "max-submit-block-body-size",
				Value:   10, // 10 MB
				EnvVars: []string{"MAX_SUBMIT_BLOCK_BODY_SIZE"},
			},
		},
		Action: func(c *cli.Context) error {
			defer zap.L().Sync() // nolint:errcheck

			cfg := loadConfig(c)

			logger.SetVersion(cfg.ShaVersion)

			if len(cfg.Beacons) == 0 {
				return ErrNoBeaconsProvided
			}

			if cfg.SecretKey == "" {
				return ErrNoSecretKeyProvided
			}

			dsk, err := hexutil.Decode(cfg.SecretKey)
			if err != nil {
				return err
			}
			secretKey, err := bls.SecretKeyFromBytes(dsk[:])
			if err != nil {
				return err
			}

			blsKey, err := bls.PublicKeyFromSecretKey(secretKey)
			if err != nil {
				return err
			}
			publicKey, err := types.BlsPublicKeyToPublicKey(blsKey)
			if err != nil {
				return err
			}

			relayCfg, err := relay.NewRelayConfig(cfg.Network, cfg.BlockSimURL, &publicKey, secretKey)
			if err != nil {
				return err
			}

			_, err = os.Stat(cfg.DBDir)
			if os.IsNotExist(err) {
				err = os.MkdirAll(cfg.DBDir, os.ModePerm)
				if err != nil {
					return err
				}
			}

			exporter, err := jaeger.New(jaeger.WithAgentEndpoint())
			if err != nil {
				logger.Error(err, "failed to create jaeger exporter")
				return err
			}

			res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String("mev-freelay"),
				attribute.Int64("chainID", int64(relayCfg.ChainID)),
			))
			if err != nil {
				logger.Error(err, "failed to create resource")
				return err
			}

			provider := sdktrace.NewTracerProvider(
				sdktrace.WithBatcher(exporter),
				sdktrace.WithResource(res),
				sdktrace.WithSampler(sdktrace.AlwaysSample()),
			)

			otel.SetTracerProvider(provider)
			defer provider.Shutdown(c.Context) // nolint:errcheck
			relayTracer := otel.Tracer("relay")
			apiTracer := otel.Tracer("webApi")

			var (
				apiAddr   = cfg.APIAddr
				relayAddr = cfg.Addr
				webAddr   = cfg.WebAddr
				sftpAddr  = cfg.SftpAddr
				prefix    = filepath.Join(cfg.DBDir, cfg.DBPrefix)
			)

			evtSender, err := relay.NewEventSender(c.Context, cfg.EventsURL)
			if err != nil {
				logger.Error(err, "failed to create event sender")
				return err
			}

			store, err := relay.NewStore(prefix)
			if err != nil {
				logger.Error(err, "failed to create store")
				return err
			}
			defer store.Close()

			known := relay.NewKnownValidators()
			active := relay.NewActiveValidators()
			duty := relay.NewDutyState()

			beacon := relay.NewMultiBeacon(cfg.Beacons)
			genesis, err := beacon.Genesis()
			if genesis == nil || err != nil {
				logger.Error(err, "failed to get genesis")
				return err
			}
			logger.Info("genesis info", "genesisTime", genesis.GenesisTime)

			if cfg.KnownValidatorsPth != "" {
				logger.Info("setting known validators", "path", cfg.KnownValidatorsPth)
				go func() {
					err = setValidatorKnownStates(known, cfg.KnownValidatorsPth)
					if err != nil {
						logger.Error(err, "failed to set known validators")
					}
				}()
			}

			runPrometheusServer(cfg.PrometheusAddr)

			apiSvc := relay.NewAPI(store, known, active, genesis.GenesisTime, cfg.Network, cfg.DBPrefix, prefix, apiTracer)
			runAPIServer(apiAddr, apiSvc)

			webSvc, err := relay.NewWeb(webAddr, apiAddr, relayAddr, prefix, cfg.Network, publicKey.String())
			if err != nil {
				logger.Error(err, "failed to create kartusche server")
				return err
			}
			runWebServer(webAddr, webSvc)

			if cfg.SftpDB {
				logger.Info("starting sftp server", "addr", sftpAddr)
				go relay.StartSFTP(c.Context, sftpAddr, store.DB()) // nolint:errcheck
			}

			maxSubmitBlockBodySizeBytes := cfg.MaxSubmitBlockBodySize * 1024 * 1024
			relaySvc, err := relay.NewRelay(store, beacon, known, active, duty, evtSender, relayCfg, genesis.GenesisTime, cfg.PprofAPI, cfg.MaxRateLimit, time.Duration(cfg.BeaconProposeTimeout), cfg.CutOffTimeout, cfg.TraceIP, cfg.AllowBuilderCancellations, maxSubmitBlockBodySizeBytes, relayTracer)
			if err != nil {
				logger.Error(err, "failed to create relay")
				return err
			}
			runRelayServer(relayAddr, cfg.ReadTimeout, cfg.ReadHeadTimeout, cfg.WriteTimeout, cfg.IdleTimeout, relaySvc)
			logger.Info("FINISHED")
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Error(err, "freelay run")
		os.Exit(1)
	}
}

func runRelayServer(addr string, readTimeout, readHeadTimeout, writeTimeout, idleTimeout uint64, r relay.Relay) {
	logger.Info("starting relay server", "address", addr)
	srv := r.HTTPServer(addr, readTimeout, readHeadTimeout, writeTimeout, idleTimeout)

	quit := make(chan os.Signal)

	go func() {
		waiter := make(chan os.Signal, 1)
		// Wait for interrupt signal to gracefully shutdown the server with
		// a timeout of 5 seconds.
		// kill (no param) default send syscanll.SIGTERM
		// kill -2 is syscall.SIGINT
		// kill -9 is syscall. SIGKILL but can"t be catch, so don't need add it
		signal.Notify(waiter, syscall.SIGINT, syscall.SIGTERM)
		<-waiter
		logger.Info("Shutdown Server ...")

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		ticker := time.NewTicker(500 * time.Millisecond)
		for {
			if err := srv.Shutdown(ctx); err != nil {
				logger.Error(err, "Server Shutdown")
			} else {
				close(quit)
				break
			}
			<-ticker.C
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error(err, "server start failed")
		os.Exit(1)
	}
	logger.Info("Server exiting")
	<-quit
	logger.Info("Server excited")
}

func runPrometheusServer(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	logger.Info("starting prometheus server", "address", addr)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			logger.Error(err, "prometheus server start failed")
			os.Exit(1)
		}
	}()
}

func runAPIServer(addr string, a relay.API) {
	logger.Info("starting api server", "address", addr)
	srv := a.HTTPServer(addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logger.Error(err, "api server start failed")
			os.Exit(1)
		}
	}()
}

func runWebServer(addr string, w relay.Web) {
	logger.Info("starting website server", "address", addr)
	go func() {
		if err := w.HTTPServer().Serve(*w.Listener()); err != nil {
			logger.Error(err, "server start failed")
			os.Exit(1)
		}
	}()
}

func setValidatorKnownStates(s relay.KnownValidatorSetter, pth string) error {
	vf, err := os.Open(pth)
	if err != nil {
		return err
	}
	defer vf.Close() // nolint:errcheck

	vb, err := io.ReadAll(vf)
	if err != nil {
		return err
	}
	var allValidators relay.AllValidatorsResponse
	if err := json.Unmarshal(vb, &allValidators); err != nil {
		return err
	}
	validators := make(map[types.PubkeyHex]relay.ValidatorResponseEntry)
	for _, v := range allValidators.Data {
		validators[types.PubkeyHex(v.Validator.Pubkey)] = v
	}

	vHexs := make(map[types.PubkeyHex]struct{})
	vByIndx := make(map[uint64]types.PubkeyHex)
	for _, v := range validators {
		vHexs[types.NewPubkeyHex(v.Validator.Pubkey)] = struct{}{}
		vByIndx[v.Index] = types.NewPubkeyHex(v.Validator.Pubkey)
	}

	s.Set(vHexs, vByIndx)
	return nil
}

type httpConfig struct {
	Addr                      string
	Network                   string
	Beacons                   []string
	PprofAPI                  bool
	SecretKey                 string
	BlockSimURL               string
	DBPrefix                  string
	DBDir                     string
	PrometheusAddr            string
	APIAddr                   string
	WebAddr                   string
	KnownValidatorsPth        string
	ShaVersion                string
	SftpAddr                  string
	SftpDB                    bool
	MaxRateLimit              uint64
	EventsURL                 string
	ReadTimeout               uint64
	ReadHeadTimeout           uint64
	WriteTimeout              uint64
	IdleTimeout               uint64
	TraceIP                   bool
	BeaconProposeTimeout      uint64
	CutOffTimeout             uint64
	AllowBuilderCancellations bool
	MaxSubmitBlockBodySize    uint64
}

func loadConfig(c *cli.Context) (config httpConfig) {
	config = httpConfig{
		Addr:                      c.String("addr"),
		Network:                   c.String("network"),
		Beacons:                   c.StringSlice("beacons"),
		PprofAPI:                  c.Bool("pprof-api"),
		SecretKey:                 c.String("secret-key"),
		BlockSimURL:               c.String("block-sim-url"),
		DBPrefix:                  c.String("db-prefix"),
		DBDir:                     c.String("db-dir"),
		PrometheusAddr:            c.String("prometheus-addr"),
		APIAddr:                   c.String("api-addr"),
		WebAddr:                   c.String("web-addr"),
		KnownValidatorsPth:        c.String("known-validators-pth"),
		ShaVersion:                c.String("sha-version"),
		SftpAddr:                  c.String("sftp-addr"),
		SftpDB:                    c.Bool("sftp-db"),
		MaxRateLimit:              c.Uint64("max-rate-limit"),
		EventsURL:                 c.String("events-url"),
		ReadTimeout:               c.Uint64("read-timeout"),
		ReadHeadTimeout:           c.Uint64("read-head-timeout"),
		WriteTimeout:              c.Uint64("write-timeout"),
		IdleTimeout:               c.Uint64("idle-timeout"),
		TraceIP:                   c.Bool("trace-ip"),
		BeaconProposeTimeout:      c.Uint64("beacon-propose-timeout"),
		CutOffTimeout:             c.Uint64("cut-off-timeout"),
		AllowBuilderCancellations: c.Bool("allow-builder-cancellations"),
		MaxSubmitBlockBodySize:    c.Uint64("max-submit-block-body-size"),
	}

	return
}
