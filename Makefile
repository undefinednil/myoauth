BINARY := myoauth$(shell go env GOEXE)

# Enable the race detector when a C compiler is available (it needs cgo).
RACE := $(shell command -v gcc >/dev/null 2>&1 && echo -race)

.PHONY: web build test vet docker compose-up compose-down

web:
	@if [ ! -d frontend/node_modules ]; then npm --prefix frontend ci; fi
	rm -rf web/dist/assets
	npm --prefix frontend run build

build: web
	go build -o $(BINARY) .

test:
	go test ./... -count=1 $(RACE)

vet:
	go vet ./...

docker:
	@command -v docker >/dev/null 2>&1 || { \
		echo "docker not found on PATH; install Docker to build the image."; \
		exit 1; \
	}
	docker build -t myoauth:latest .

compose-up:
	@command -v docker >/dev/null 2>&1 || { \
		echo "docker not found on PATH; install Docker to use compose."; \
		exit 1; \
	}
	docker compose up -d --build

compose-down:
	@command -v docker >/dev/null 2>&1 || { \
		echo "docker not found on PATH; install Docker to use compose."; \
		exit 1; \
	}
	docker compose down
