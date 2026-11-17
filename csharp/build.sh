#!/usr/bin/env bash
# Builds the release binaries of ipxserver for all supported platforms.
# For Linux; on Windows use build.ps1 instead. The GitHub release workflow
# uses this script, too.
#
# Usage:
#   ./build.sh [--version X.Y.Z] [--package] [--skip-tests] [RID...]
#
#   --version X.Y.Z  Version number to compile into the binaries
#                    (default: the one from Directory.Build.props)
#   --package        Additionally create one archive per platform plus a
#                    SHA256SUMS.txt in dist/ (.zip for Windows, .tar.gz else)
#   --skip-tests     Do not run the tests first
#   RID...           The platforms (.NET runtime identifiers) to build for,
#                    default: win-x64 linux-x64 linux-arm64 linux-arm
#
# Result: dist/<RID>/ipxserver[.exe], one self-contained executable each.
# .NET can build for all platforms from any platform, so no cross compiler or
# the like is needed.

set -euo pipefail
cd "$(dirname "$0")"

VERSION=""
PACKAGE=false
RUN_TESTS=true
RIDS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --version)    VERSION="$2"; shift ;;
        --package)    PACKAGE=true ;;
        --skip-tests) RUN_TESTS=false ;;
        -h|--help)    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)           echo "Unknown option: $1" >&2; exit 2 ;;
        *)            RIDS+=("$1") ;;
    esac
    shift
done
[ ${#RIDS[@]} -gt 0 ] || RIDS=(win-x64 linux-x64 linux-arm64 linux-arm)

# Only pass a version on to dotnet if one was given.
VERSION_ARGS=()
[ -z "$VERSION" ] || VERSION_ARGS=("-p:Version=$VERSION")

if $RUN_TESTS; then
    echo "### Running tests"
    dotnet run --project tests/ipxserver.Tests -c Release
fi

rm -rf dist
for RID in "${RIDS[@]}"; do
    echo "### Publishing for $RID"
    dotnet publish src/ipxserver -c Release -r "$RID" -o "dist/$RID" ${VERSION_ARGS[@]+"${VERSION_ARGS[@]}"}
done

if $PACKAGE; then
    # Name of the archives: ipxserver-<version>-<rid>.<ext>
    NAME_VERSION="${VERSION:-$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' Directory.Build.props)}"
    for RID in "${RIDS[@]}"; do
        BASE="ipxserver-$NAME_VERSION-$RID"
        # Add the documentation and the systemd unit to each archive.
        cp README.md "dist/$RID/"
        case "$RID" in
            win-*)
                echo "### Packaging $BASE.zip"
                (cd "dist/$RID" && zip -q -r "../$BASE.zip" .)
                ;;
            *)
                echo "### Packaging $BASE.tar.gz"
                cp contrib/ipxserver.service "dist/$RID/"
                # tar keeps the "executable" flag of the binary.
                tar -C "dist/$RID" -czf "dist/$BASE.tar.gz" .
                ;;
        esac
    done
    (cd dist && sha256sum ipxserver-* > SHA256SUMS.txt)
fi

echo "### Done. Results are in $(pwd)/dist"
