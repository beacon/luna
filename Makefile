REF ?= $(shell git describe --tags || git branch --show-current)
COMMIT ?= $(shell git rev-parse --short HEAD)
TREESTATE ?= $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
DATE ?= $(shell TZ='Asia/Shanghai' date '+%Y-%m-%d_%H:%M:%S')
REPO ?= docker.io/et1989
IMG ?= $(REPO)/luna:$(REF)

PKG=github.com/beacon/luna
luna:
	#go mod vendor
	go build -mod=vendor -ldflags=" \
	-X $(PKG)/pkg/version.GitVersion=$(REF) \
	-X $(PKG)/pkg/version.GitCommit=$(COMMIT) \
	-X $(PKG)/pkg/version.GitTreeState=$(TREESTATE) \
	-X $(PKG)/pkg/version.BuildDate=$(DATE)" \
	-o bin/luna \
	./cmd/luna

image:
	docker build -t=$(IMG) .

.PHONY: luna
