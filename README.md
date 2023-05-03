# IMPORTANT - Use at Your Own Risk!!!

Please note that this relay has not been subjected to a security audit, and as such, there may exist security or other vulnerabilities that have not been discovered or addressed. By using this relay, there is a risk that your or your clients' assets could be compromised. Therefore, you use this relay at your own risk.

# Relays

- https://goerli-relay.securerpc.com/
- https://goerli.securerpc.com/

# Code Guides

- https://google.github.io/styleguide/go/ # best-practises
- https://github.com/golang/go/wiki

# USP (Unique Selling Points)

- Use of a single process and embedded bbolt database for persistence, leading to lower latency and resource usage for operations
- Automatic archiving of submitted payloads to S3, which keeps the operation database length constant
- Simple backup and restore process

# Tech Stack

We aimed for a straightforward technology stack that is easy to manage and deploy. For handling **API** requests, we chose [httprouter](https://github.com/julienschmidt/httprouter). We chose [bbolt](https://github.com/etcd-io/bbolt) as our database due to its fast read speeds. We wrapped it with [bolted](https://github.com/draganm/bolted) for greater control over read and write operations. Finally, we used [kartusche](https://github.com/numtide/kartusche) to build the website, which utilizes [mustache](https://mustache.github.io/) templating.

# Build

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

# CLI

## Generate Keys

```
go run cmd/keys/main.go
```

## Backup Database to S3

It is using default `AWS` credentials. You can override them with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

```
go run cmd/backup/main.go --backup-url http://localhost:50052/backup --bucket <bucket>
```

## Restore Database from S3

It is using default `AWS` credentials. You can override them with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

```
go run cmd/restore/main.go --db-dir <dir> --db-prefix <prefix> --bucket <bucket>
```

## Purge Database

Archives payloads (executed-payloads, submitted, bid-traces) that are older then 6 hours in a `.tar.gz` file and uploads it to S3 and deletes them from the database.

It is using default `AWS` credentials. You can override them with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

```
go run cmd/purge/main.go --archive-url http://localhost:50052/archive --prune-url http://localhost:50052/prune  --bucket <bucket>
```

## Compact Database

```
go run cmd/compact/main.go --db-dir <dir> --db-prefix <prefix>
```

## Migrate Database

```
go run cmd/migrate/main.go --db-dir <dir> --db-prefix <prefix>
```

## Import Delivered Payloads

```
go run cmd/import/main.go --db-dir <dir> --db-prefix <prefix> --file <file> --sql-uri <sql-uri> --sql-table <dev_payload_delivered>
```

# Builder Specs

https://github.com/ethereum/builder-specs

# Beacon API

https://ethereum.github.io/beacon-APIs/#/

# TODO

- Replace `go-boost-tools` with `https://github.com/attestantio/go-eth2-client/tree/master/spec`
