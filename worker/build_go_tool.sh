#!/bin/sh
# Builds one of the worker's Go recon tools, in worker/Dockerfile's `tools` stage
# (docs/SUPPLY_CHAIN.md, "The Go recon tools").
#
#   build_go_tool.sh <package>@<release> [<module>@<version>...]
#
# With no module after the release: `go install <package>@<release>`, the tool exactly as its
# go.mod and go.sum say. With modules: the same release, built with those dependencies raised
# to the versions given (a fixed advisory the tool's authors have not released yet). A
# throwaway module requires the release as a tool (`go get -tool`), then the raised versions,
# and builds the tool's package; Go's minimal version selection keeps every other dependency at
# the version the release asks for, or the lowest one a raised module needs. Every module
# downloaded is checked against the public checksum database (the stage's GOSUMDB, with no
# GONOSUMDB, GOPRIVATE or GOINSECURE), as `go install` checks it against the tool's go.sum and
# the same database. The build fails if a raised module ends up at any other version than the
# one given. The binary's build information lists the tool's release as a dependency, so the
# image scan and the SBOM still see it, with every module and its version.
set -eu
[ "$#" -ge 1 ] || { echo "usage: $0 <package>@<release> [<module>@<version>...]" >&2; exit 2; }
tool="$1"; shift
pkg="${tool%@*}"
name="${pkg##*/}"
case "$tool" in *@v*) ;; *) echo "$tool: give an exact release (@vX.Y.Z)" >&2; exit 2 ;; esac
if [ "$#" -eq 0 ]; then
  go install "$tool"
  exit 0
fi
dir="$(mktemp -d)"
cd "$dir"
go mod init "attackledger.invalid/worker-tools/$name"
go get -tool "$tool"
go get "$@"
go mod tidy
for m in "$@"; do
  case "$m" in *@v*) ;; *) echo "$m: give an exact version (@vX.Y.Z)" >&2; exit 2 ;; esac
  got="$(go list -m -f '{{.Path}}@{{.Version}}' "${m%@*}")"
  [ "$got" = "$m" ] || { echo "$name: $m asked for, $got selected" >&2; exit 1; }
done
got="$(go list -m -f '{{.Version}}' "$(go list -f '{{.Module.Path}}' "$pkg")")"
[ "$got" = "${tool##*@}" ] || { echo "$name: release ${tool##*@} asked for, $got selected" >&2; exit 1; }
go build -o "$(go env GOPATH)/bin/$name" "$pkg"
cd /
rm -rf "$dir"
