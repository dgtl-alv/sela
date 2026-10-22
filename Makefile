.PHONY: test vet build compose-up compose-down

test:
	go test -race ./...

vet:
	go vet ./...

build:
	go build ./cmd/server

compose-up:
	docker compose up --build

compose-down:
	docker compose down
