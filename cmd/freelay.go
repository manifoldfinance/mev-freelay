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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	relay "github.com/manifoldfinance/mev-freelay/freelay"
	"github.com/manifoldfinance/mev-freelay/logger"
	"github.com/manifoldfinance/mev-freelay/web"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func Freelay() *cli.Command {
	return &cli.Command{
		Name:  "freelay",
		Usage: "relay, api, sftp services with prometheus",
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
				Name:    "enable-pprof",
				Value:   false,
				EnvVars: []string{"ENABLE_PPROF"},
			},
			&cli.StringFlag{
				Name:    "pprof-addr",
				Value:   ":6060",
				EnvVars: []string{"PPROF_ADDR"},
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
				Name:    "db-pth",
				Value:   "dbs/prod_db",
				EnvVars: []string{"DB_PTH"},
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
				Name:    "known-validators-pth",
				EnvVars: []string{"KNOWN_VALIDATORS_PTH"},
			},
			&cli.StringFlag{
				Name:    "sha-version",
				Value:   "unknown",
				EnvVars: []string{"SHA_VERSION"},
			},
			&cli.Uint64Flag{
				Name:    "max-rate-limit",
				Value:   0,
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
			// "Maximum number of bytes the server will read parsing the request header's keys and values, including the request line. It does not limit the size of the request body.",
			&cli.Uint64Flag{
				Name:    "max-header-bytes",
				Value:   60_000,
				EnvVars: []string{"MAX_HEADER_BYTES"},
			},
			// "Timeout on how long to wait for the beacon to propagate the new block over p2p to other nodes in milliseconds.",
			&cli.Uint64Flag{
				Name:    "beacon-propose-timeout",
				Value:   1000,
				EnvVars: []string{"BEACON_PROPOSE_TIMEOUT"},
			},
			// "Timeout on how long to wait for the builder to simulate the block in milliseconds.",
			&cli.Uint64Flag{
				Name:    "builder-block-sim-timeout",
				Value:   10_000,
				EnvVars: []string{"BUILDER_BLOCK_SIM_TIMEOUT"},
			},
			&cli.Uint64Flag{
				Name:    "cut-off-timeout-header",
				Value:   3000,
				EnvVars: []string{"CUT_OFF_TIMEOUT_HEADER"},
			},
			&cli.Uint64Flag{
				Name:    "cut-off-timeout-payload",
				Value:   4000,
				EnvVars: []string{"CUT_OFF_TIMEOUT_PAYLOAD"},
			},
			&cli.Uint64Flag{
				Name:    "get-payload-retry-max",
				Value:   3,
				EnvVars: []string{"GET_PAYLOAD_RETRY_MAX"},
			},
			&cli.Uint64Flag{
				Name:    "get-payload-retry-ms",
				Value:   100,
				EnvVars: []string{"GET_PAYLOAD_RETRY_MS"},
			},
			&cli.BoolFlag{
				Name:    "trace-ip",
				Value:   false,
				EnvVars: []string{"TRACE_IP"},
			},
			&cli.Uint64Flag{
				Name:    "max-submit-block-body-size",
				Value:   10, // 10 MB
				EnvVars: []string{"MAX_SUBMIT_BLOCK_BODY_SIZE"},
			},
			&cli.Uint64Flag{
				Name:    "max-ch-queue",
				Value:   10_000,
				EnvVars: []string{"MAX_CH_QUEUE"},
			},
			&cli.Uint64Flag{
				Name:    "beacon-validators-timeout",
				Value:   20, // seconds
				EnvVars: []string{"BEACON_VALIDATORS_TIMEOUT"},
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

			_, err = os.Stat(cfg.DBPth)
			if os.IsNotExist(err) {
				err = os.MkdirAll(cfg.DBPth, os.ModePerm)
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

			evtSender, err := relay.NewEventSender(c.Context, cfg.EventsURL)
			if err != nil {
				logger.Error(err, "failed to create event sender")
				return err
			}

			store, err := relay.NewPebbleDB(cfg.DBPth, true)
			if err != nil {
				logger.Error(err, "failed to create store")
				return err
			}
			defer store.Close()

			known := relay.NewKnownValidators()
			duty := relay.NewDutyState()

			beacon := relay.NewMultiBeacon(cfg.Beacons, cfg.BeaconValidatorsTimeout)
			genesis, err := beacon.Genesis()
			if genesis == nil || err != nil {
				logger.Error(err, "failed to get genesis")
				return err
			}
			logger.Info("genesis info", "genesisTime", genesis.GenesisTime)

			syncNode, err := beacon.BestSyncingNode()
			if err != nil {
				return err
			}
			logger.Info("syncing node", "headSlot", syncNode.Data.HeadSlot)

			builderBlockSimulator := relay.NewBuilderBlockSimulator(time.Duration(cfg.BuilderBlockSimTimeout)*time.Millisecond, cfg.BlockSimURL)

			if cfg.KnownValidatorsPth != "" {
				logger.Info("setting known validators", "path", cfg.KnownValidatorsPth)
				go func() {
					err = setValidatorKnownStates(known, cfg.KnownValidatorsPth)
					if err != nil {
						logger.Error(err, "failed to set known validators")
					}
				}()
			}

			eg, ctx := errgroup.WithContext(c.Context)

			maxSubmitBlockBodySizeBytes := cfg.MaxSubmitBlockBodySize * 1024 * 1024
			relaySvc, err := relay.NewRelay(
				ctx,
				store,
				beacon,
				builderBlockSimulator,
				known,
				duty,
				evtSender,
				relayCfg,
				genesis.GenesisTime, syncNode.Data.HeadSlot,
				cfg.MaxChQueue, cfg.MaxRateLimit, cfg.BeaconProposeTimeout, cfg.CutOffTimeoutHeader, cfg.CutOffTimeoutPayload, maxSubmitBlockBodySizeBytes, cfg.GetPayloadRetryMax, cfg.GetPayloadRetryMS,
				cfg.TraceIP,
				relayTracer,
			)
			if err != nil {
				logger.Error(err, "failed to create relay")
				return err
			}

			api := relay.NewAPI(store, known, genesis.GenesisTime, cfg.Network, publicKey, apiTracer)
			web, err := web.NewHandler(*logger.Z(), api.Handler())
			if err != nil {
				logger.Error(err, "failed to create web handler")
				return err
			}

			eg.Go(func() error {
				return runPrometheusServer(ctx, cfg.PrometheusAddr)
			})

			if cfg.EnablePprof {
				eg.Go(func() error {
					return runPprofServer(ctx, cfg.PprofAddr)
				})
			}

			eg.Go(func() error {
				return runAPIServer(ctx, cfg.APIAddr, web)
			})

			eg.Go(func() error {
				return runRelayServer(ctx, cfg.Addr, cfg.ReadTimeout, cfg.ReadHeadTimeout, cfg.WriteTimeout, cfg.IdleTimeout, cfg.MaxHeaderBytes, relaySvc)
			})

			eg.Go(func() error {
				sigs := make(chan os.Signal, 1)
				signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

				select {
				case sig := <-sigs:
					logger.Info("signal received, terminating", "sig", sig)
					return fmt.Errorf("signal %s received", sig.String())
				case <-ctx.Done():
					return ctx.Err()
				}
			})

			return eg.Wait()
		},
	}
}

func runRelayServer(ctx context.Context, addr string, readTimeout, readHeadTimeout, writeTimeout, idleTimeout, maxHeaderBytes uint64, r relay.Relay) error {
	logger.Info("starting relay server", "address", addr)
	srv := r.HTTPServer(addr, readTimeout, readHeadTimeout, writeTimeout, idleTimeout, maxHeaderBytes)

	name := "relay"

	go func() {
		<-ctx.Done()

		// wait until all the jobs are finished
		r.Stop()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		logger.Info(fmt.Sprintf("graceful shutdown of the %s server", name))
		err := srv.Shutdown(shutdownCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			logger.Info(fmt.Sprintf("%s server did not shut down gracefully, forcing close", name))
			srv.Close() // nolint:errcheck
		}
	}()

	return srv.ListenAndServe()
}

func runPprofServer(ctx context.Context, addr string) error {
	logger.Info("starting pprof server", "address", addr)
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go shutdown(ctx, "pprof", srv)

	return srv.ListenAndServe()
}

func runPrometheusServer(ctx context.Context, addr string) error {
	logger.Info("starting prometheus server", "address", addr)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go shutdown(ctx, "prometheus", srv)

	return srv.ListenAndServe()
}

func runAPIServer(ctx context.Context, addr string, handler http.Handler) error {
	logger.Info("starting api server", "address", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go shutdown(ctx, "api", srv)

	return srv.ListenAndServe()
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
	var allValidators relay.KnownValidatorsResponse
	if err := json.Unmarshal(vb, &allValidators); err != nil {
		return err
	}
	validators := make(map[types.PubkeyHex]relay.ValidatorResponseEntry)
	for _, v := range allValidators.Data {
		validators[types.PubkeyHex(v.Validator.Pubkey)] = v
	}

	vHexs := make(map[types.PubkeyHex]uint64)
	vByIndx := make(map[uint64]types.PubkeyHex)
	for _, v := range validators {
		pk := types.NewPubkeyHex(v.Validator.Pubkey)
		vHexs[pk] = v.Index
		vByIndx[v.Index] = pk
	}

	s.Set(vHexs, vByIndx, 0)
	return nil
}

type httpConfig struct {
	Addr                    string
	Network                 string
	Beacons                 []string
	EnablePprof             bool
	PprofAddr               string
	SecretKey               string
	BlockSimURL             string
	DBPth                   string
	PrometheusAddr          string
	APIAddr                 string
	KnownValidatorsPth      string
	ShaVersion              string
	MaxRateLimit            uint64
	EventsURL               string
	ReadTimeout             uint64
	ReadHeadTimeout         uint64
	WriteTimeout            uint64
	IdleTimeout             uint64
	MaxHeaderBytes          uint64
	BuilderBlockSimTimeout  uint64
	GetPayloadRetryMax      uint64
	GetPayloadRetryMS       uint64
	BeaconProposeTimeout    uint64
	CutOffTimeoutHeader     uint64
	CutOffTimeoutPayload    uint64
	MaxSubmitBlockBodySize  uint64
	MaxChQueue              uint64
	TraceIP                 bool
	BeaconValidatorsTimeout uint64
}

func loadConfig(c *cli.Context) (config httpConfig) {
	config = httpConfig{
		Addr:                    c.String("addr"),
		Network:                 c.String("network"),
		Beacons:                 c.StringSlice("beacons"),
		EnablePprof:             c.Bool("enable-pprof"),
		PprofAddr:               c.String("pprof-addr"),
		SecretKey:               c.String("secret-key"),
		BlockSimURL:             c.String("block-sim-url"),
		DBPth:                   c.String("db-pth"),
		PrometheusAddr:          c.String("prometheus-addr"),
		APIAddr:                 c.String("api-addr"),
		KnownValidatorsPth:      c.String("known-validators-pth"),
		ShaVersion:              c.String("sha-version"),
		MaxRateLimit:            c.Uint64("max-rate-limit"),
		EventsURL:               c.String("events-url"),
		ReadTimeout:             c.Uint64("read-timeout"),
		ReadHeadTimeout:         c.Uint64("read-head-timeout"),
		WriteTimeout:            c.Uint64("write-timeout"),
		IdleTimeout:             c.Uint64("idle-timeout"),
		MaxHeaderBytes:          c.Uint64("max-header-bytes"),
		BuilderBlockSimTimeout:  c.Uint64("builder-block-sim-timeout"),
		GetPayloadRetryMax:      c.Uint64("get-payload-retry-max"),
		GetPayloadRetryMS:       c.Uint64("get-payload-retry-ms"),
		BeaconProposeTimeout:    c.Uint64("beacon-propose-timeout"),
		CutOffTimeoutHeader:     c.Uint64("cut-off-timeout-header"),
		CutOffTimeoutPayload:    c.Uint64("cut-off-timeout-payload"),
		MaxSubmitBlockBodySize:  c.Uint64("max-submit-block-body-size"),
		MaxChQueue:              c.Uint64("max-ch-queue"),
		TraceIP:                 c.Bool("trace-ip"),
		BeaconValidatorsTimeout: c.Uint64("beacon-validators-timeout"),
	}

	return
}
