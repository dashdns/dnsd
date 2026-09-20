# dnsd AMI build.
#
#   make init          install the Packer plugins
#   make package       tar the working tree for upload (build does this for you)
#   make validate      syntax + variable check (no AWS resources created)
#   make build         build both architectures
#   make build-amd64   build amd64 only
#   make clean         remove local build artifacts
#
# Requires: packer >= 1.9, AWS credentials with EC2 image-build permissions.

SHELL := /bin/bash

PACKER      ?= packer
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REGION      ?= eu-central-1
PACKER_LOG  ?= 0

# PACKER_EXTRA passes arbitrary extra flags through, e.g.
#   make build-amd64 PACKER_EXTRA="-var 'debug_password=hunter2hunter2'"
PACKER_EXTRA ?=

VARS := -var 'dnsd_version=$(VERSION)' -var 'region=$(REGION)' $(PACKER_EXTRA)

export PACKER_LOG

.PHONY: help
help:
	@sed -n '2,10p' $(MAKEFILE_LIST) | sed 's/^# \{0,1\}//'
	@echo
	@echo "Current: VERSION=$(VERSION) REGION=$(REGION)"

.PHONY: init
init:
	$(PACKER) init .

.PHONY: fmt
fmt:
	$(PACKER) fmt .

.PHONY: fmt-check
fmt-check:
	$(PACKER) fmt -check -diff .

.PHONY: lint
lint:
	@command -v shellcheck >/dev/null 2>&1 \
		|| { echo "shellcheck not installed; skipping"; exit 0; }
	shellcheck -x scripts/*.sh files/usr/local/sbin/dnsd-tune-*

# Package the working tree for upload.
#
# Must happen before packer runs: the file provisioner stats its source during
# Prepare, before any provisioner executes. Uses tar rather than `git archive`
# so uncommitted changes make it into the image. Not .PHONY on purpose — the
# tarball is a real artifact — but always rebuilt, since tracking every source
# file as a prerequisite is not worth it for a 1 MB repo.
TARBALL := .artifacts/dnsd-src.tar.gz

.PHONY: package
package:
	@mkdir -p .artifacts
	@COPYFILE_DISABLE=1 tar -czf $(TARBALL) -C .. \
		--exclude='.git' \
		--exclude='build/.artifacts' \
		--exclude='./dnsd' \
		.
	@echo "packaged $(TARBALL) ($$(du -h $(TARBALL) | cut -f1))"

.PHONY: validate
validate: init package
	$(PACKER) validate $(VARS) .

.PHONY: build
build: validate
	$(PACKER) build $(VARS) .

.PHONY: build-amd64
build-amd64: validate
	$(PACKER) build -only='dnsd.amazon-ebs.amd64' $(VARS) .

.PHONY: build-arm64
build-arm64: validate
	$(PACKER) build -only='dnsd.amazon-ebs.arm64' $(VARS) .

# Keep the builder alive on failure so the guest can be inspected over SSH.
.PHONY: debug
debug: init package
	PACKER_LOG=1 $(PACKER) build -on-error=ask -only='dnsd.amazon-ebs.amd64' $(VARS) .

.PHONY: manifest
manifest:
	@test -f .artifacts/manifest.json \
		&& cat .artifacts/manifest.json \
		|| echo "no manifest yet — run make build"

.PHONY: clean
clean:
	rm -rf .artifacts packer_cache crash.log
