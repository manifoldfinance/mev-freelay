clean:
	find . -name \test.*.db -type f -delete
	find . -name \fake.*.db -type f -delete
	find . -name \test_*_db -type d -exec rm -r {} +
	find . -name \fake_*_db -type d -exec rm -r {} +

minio:
	docker compose -f minio.yaml up -d

ingress:
	docker compose -f ingress.yaml up -d

swag:
	docker compose -f swag.yaml down --remove-orphans
	docker compose -f swag.yaml up -d

fmt:
	golangci-lint run && treefmt

license:
	./scripts/license.sh ./cmd update
	./scripts/license.sh ./logger update
	./scripts/license.sh ./freelay update
	./scripts/license.sh ./web update