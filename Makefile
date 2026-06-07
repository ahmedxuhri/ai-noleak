.PHONY: all build test clean

GO ?= /usr/local/go/bin/go
BIN_DIR := bin
CMDS := noleakd noleak-watch noleak

all: build

build:
	@mkdir -p $(BIN_DIR)
	@for cmd in $(CMDS); do \
		echo "  build  $$cmd"; \
		$(GO) build -o $(BIN_DIR)/$$cmd ./cmd/$$cmd || exit 1; \
	done

test:
	$(GO) test ./...

clean:
	rm -rf $(BIN_DIR)

vet:
	$(GO) vet ./...
