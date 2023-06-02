PROJECT        :=safe
DESTDIR        ?=/usr/local
RELEASE_ROOT   ?=release
TARGETS        ?=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
SAFE_PATH      ?=./$(PROJECT)
VAULT_VERSIONS ?=

GO_LDFLAGS := -ldflags="-X main.Version=$(VERSION)"

.PHONY: use build test install require-% release-% clean
use:
	@echo "Using $(shell $(SAFE_PATH) -v 2>&1) at location $(SAFE_PATH)"

build:
	go build $(GO_LDFLAGS) -o $(SAFE_PATH)
	$(SAFE_PATH) -v

test: $(if $(wildcard $(SAFE_PATH)),use,build)
	./tests $(SAFE_PATH) ${VAULT_VERSIONS}

install: build
	mkdir -p $(DESTDIR)/bin
	cp safe $(DESTDIR)/bin

require-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
	fi

RELEASES := $(foreach target,$(TARGETS),release-$(target)-$(PROJECT))

release-all: $(RELEASES)

define build-target
release-$(1)/$(2)-$(PROJECT): require-VERSION
	@echo "Building $(PROJECT) $(VERSION) ($(1)/$(2)) ..." 
	GOOS=$(1) GOARCH=$(2) go build -o $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-$(1)-$(2) $(GO_LDFLAGS)
	@ls -la $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-$(1)-$(2)
	@echo ""
endef

$(foreach target,$(TARGETS),$(eval $(call build-target,$(word 1, $(subst /, ,$(target))),$(word 2, $(subst /, ,$(target))))))

clean:
	rm -rf $(SAFE_PATH) $(RELEASE_ROOT) 

.DEFAULT_GOAL := release-al
