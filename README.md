# IMPORTANT - Use at Your Own Risk!!!

Please note that this relay has not been subjected to a security audit, and as such, there may exist security or other vulnerabilities that have not been discovered or addressed. By using this relay, there is a risk that your or your clients' assets could be compromised. Therefore, you use this relay at your own risk.

# Relays

- https://goerli-relay.securerpc.com/
- https://goerli.securerpc.com/

# Code Guides

- https://google.github.io/styleguide/go/ # best-practises
- https://github.com/golang/go/wiki

# USP (Unique Selling Points)

- Use of a single process and embedded pebble database for persistence, leading to lower latency and resource usage for operations
- Automatic archiving of submitted payloads to S3, which keeps the operation database length constant
- Simple backup and restore process

# Tech Stack

We aimed for a straightforward technology stack that is easy to manage and deploy. We chose [pebble](https://github.com/cockroachdb/pebble) as our database due to its fast read speeds and multi threaded writes. Finally, we used [go-lean](https://github.com/draganm/go-lean) to build the website, which utilizes [mustache](https://mustache.github.io/) templating.

# Production

## Using Dockerfile

```
DOCKER_BUILDKIT=1 docker build -t mev-freelay .
docker run mev-freelay freelay -e BEACONS <prysm_beacon_url> -e BLOCK_SIM_URL <geth_url> -e SECRET_KEY <generate with keys> -e NETWORK goerli -e DB_PTH dbs/prod_db
```

## Using binary

```
go build -o mev-freelay .
./mev-freelay freelay --beacons <prysm_beacon_url> --block-sim-url <geth_url> --secret-key <generate with keys> --network goerli --db-pth dbs/prod_db
```

# Development

```
go run main.go freerelay --beacons <prysm_beacon_url> --block-sim-url <geth_url> --secret-key <generate with keys> --network goerli --db-pth dbs/prod_db
```

Relay (Proposer, Builder, Data): http://localhost:50051
API (Website): http://localhost:50052
Prometheus: http://localhost:9000
PPROF: http://localhost:6060

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

# CLI

## Generate Keys

```
go run main.go keys
```

## Backup Database to S3

It is using default `AWS` credentials. You can override them with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

```
go run main.go backup --backup-url http://localhost:50052/api/backup --bucket <bucket>
```

## Restore Database from S3

It is using default `AWS` credentials. You can override them with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

```
go run main.go restore --db-pth <db_pth> --bucket <bucket>
```

## Purge Database

Archives payloads (executed-payloads, submitted, bid-traces) that are older then 6 hours in a `.tar.gz` file and uploads it to S3 and deletes them from the database.

It is using default `AWS` credentials. You can override them with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

```
go run main.go purge --archive-url http://localhost:50052/api/archive --prune-url http://localhost:50052/api/prune --bucket <bucket>
```

## Migrate Database (bbolt -> pebble)

```
go run main.go migrate --bbolt-pth <bbolt_pth> --pebble-pth <pebble_pth>
```

## Import Database (postgres -> pebble)

```
go run main.go import --db-pth <db_pth> --sql-uri <sql_uri> --sql-table-prefix <dev>
```

# Builder Specs

https://github.com/ethereum/builder-specs

# Beacon API

https://ethereum.github.io/beacon-APIs/#/

# TODO

- Replace `go-boost-tools` with `https://github.com/attestantio/go-eth2-client/tree/master/spec`
