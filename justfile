# Development task runner for counterspy.
#
# The `ci` recipe replicates .github/workflows/ci.yml so a branch can be validated
# locally before a merge. `checks` mirrors the reusable .github/workflows/checks.yml
# gate that both CI and Release call.
#
# Recipes NOT part of CI parity (lint, arch, and the dev conveniences) are kept out
# of `ci` on purpose: `just ci` passing must mean "GitHub will pass", nothing looser.

# Race detection needs cgo, and the code-signature checks call Security.framework
# through it. checks.yml sets this for the same reason.
export CGO_ENABLED := "1"

# Coverage gate enforced by checks.yml.
COVERAGE_MIN := "80.0"

COVERAGE_FILE := "coverage.out"

# Go files the project owns — vendor/ is checked in and must not gate the build.
owned_go_files := "git ls-files '*.go' | grep -v '^vendor/'"

_default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# CI parity — these mirror the GitHub workflows exactly.
# ---------------------------------------------------------------------------

# Full local replica of ci.yml (checks + release build). Run before a merge.
ci: checks release-build
    @echo "✓ ci: local replica of .github/workflows/ci.yml passed"

# The reusable gate from checks.yml: gofmt, vet, build, race tests, coverage.
checks: fmt-check vet build cover
    @echo "✓ checks: local replica of .github/workflows/checks.yml passed"

# Fail if any owned Go file is not gofmt-clean (checks.yml "gofmt" step).
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    unformatted="$(gofmt -l $({{ owned_go_files }}))"
    if [ -n "$unformatted" ]; then
        echo "These files are not gofmt-clean:"
        echo "$unformatted"
        exit 1
    fi
    echo "gofmt: clean"

vet:
    go vet ./...

build:
    go build ./...

# Race + atomic coverage profile (checks.yml "test (race + coverage)" step).
test:
    go test ./... -race -covermode=atomic -coverprofile={{ COVERAGE_FILE }}

# Enforce the coverage gate (checks.yml "coverage gate" step).
cover: test
    #!/usr/bin/env bash
    set -euo pipefail
    total="$(go tool cover -func={{ COVERAGE_FILE }} | tail -1 | grep -oE '[0-9.]+%' | tr -d '%')"
    echo "Total coverage: ${total}%"
    awk "BEGIN { exit !(${total} >= {{ COVERAGE_MIN }}) }" || {
        echo "error: coverage ${total}% is below the {{ COVERAGE_MIN }}% gate"
        exit 1
    }

# Snapshot release build, no publish — validates .goreleaser.yaml (ci.yml "release-build" job).
release-build:
    goreleaser release --snapshot --clean

# ---------------------------------------------------------------------------
# Not run by CI.
# ---------------------------------------------------------------------------

# Rewrite owned Go files in gofmt style.
fmt:
    @gofmt -w $({{ owned_go_files }})

# golangci-lint. Not a merge gate — CI does not run it.
lint:
    golangci-lint run

# Validate the Architext architecture data (required by CLAUDE.md after doc edits).
arch:
    architext validate

# Serve the Architext viewer for review.
arch-serve:
    architext serve

# Run tests matching a name pattern, verbosely. Usage: just test-one TestFoo
test-one pattern:
    go test ./... -run '{{ pattern }}' -race -v

# Open the HTML coverage report from the last `just test` run.
cover-html: test
    go tool cover -html={{ COVERAGE_FILE }}

# Remove artifacts produced by this justfile (coverage profile + goreleaser output).
clean:
    rm -f {{ COVERAGE_FILE }}
    rm -rf dist
