SHELL := /usr/bin/env bash

# Tools (CI installs them if missing)
SHELLCHECK ?= shellcheck
SHFMT ?= shfmt
BATS ?= bats

.PHONY: all fmt lint test install clean package

all: fmt lint test

fmt:
	@$(SHFMT) -w -s -i 2 -ci -bn .

lint:
	@$(SHELLCHECK) -x sentinel.sh scripts/*.sh

test:
	@$(BATS) tests

install:
	@install -m 0755 sentinel.sh /usr/local/bin/sentinel

clean:
	@rm -rf model/*.tsv report.html

package: # create a tarball for release
	@tar -czf sentinel-$(shell date +%Y%m%d).tar.gz \
		sentinel.sh README.md LICENSE Makefile scripts tests docs .github .gitignore
