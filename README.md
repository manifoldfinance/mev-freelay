# IMPORTANT - Use at Your Own Risk!!!

Please note that this relay has not been subjected to a security audit, and as such, there may exist security or other vulnerabilities that have not been discovered or addressed. By using this relay, there is a risk that your or your clients' assets could be compromised. Therefore, you use this relay at your own risk.

# Relays

- https://goerli-relay.securerpc.com/

# Code Guides

- https://google.github.io/styleguide/go/ # best-practises
- https://github.com/golang/go/wiki

# Builder Specs

https://github.com/ethereum/builder-specs

# Beacon API

https://ethereum.github.io/beacon-APIs/#/

# Building

```
DOCKER_BUILDKIT=1
export CGO_CFLAGS_ALLOW="-D__BLST_PORTABLE__"
export CGO_CFLAGS="-D__BLST_PORTABLE__"
```

# Production

## Using Dockerfile

```
DOCKER_BUILDKIT=1 docker build -t freelay .
docker run freelay -e BEACONS <prysm_beacon_url> -e BLOCK_SIM_URL <geth_url> -e SECRET_KEY <generate with cmd/keys> -e NETWORK goerli -e DB_PREFIX prod -e DB_DIR dbs
```

## Using binary

```
go build -o freelay cmd/freelay/main.go
./freelay --beacons <prysm_beacon_url> --block-sim-url <geth_url> --secret-key <generate with cmd/keys> --network goerli --db-prefix prod --db-dir dbs
```

# Development

```
go run cmd/freelay/main.go --beacons <prysm_beacon_url> --block-sim-url <geth_url> --secret-key <generate with cmd/keys> --network goerli --db-prefix prod --db-dir dbs

Relay (Proposer, Builder, Data): http://localhost:50051
API (Website API): http://localhost:50052
Website: http://localhost:50053
SFTP: http://localhost:50054
Prometheus: http://localhost:9000
```

## Minio S3

```
make minio
```

## Ingress

We believe that development env should behave the same as production. This is why we are using ingress to route traffic to the local service freelay (web, relay). This is done so we can access `relay|eth` paths from website that are running on a different domain.

Before starting the ingress you need to make sure that the ports you use for `web` and `relay` are also used in the ingress.

```
# Ingress is running on PORT 50050
make ingress
```

## Debugging

```
go install github.com/go-delve/delve/cmd/dlv@latest
go install -v golang.org/x/tools/gopls@latest
```

## Format & Lint

```
make fmt
```

## Documentation

### Swagger

```
make swag
```

# TODO

- Replace `go-boost-tools` with `https://github.com/attestantio/go-eth2-client/tree/master/spec`
