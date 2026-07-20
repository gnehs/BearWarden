#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "Skipping macOS autofill helper on $(uname -s)"
  exit 0
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(dirname -- "$script_directory")
source_file="$project_root/native/macos-autofill/main.swift"
output_file=${1:-"$project_root/resources/bin/bearwarden-macos-autofill"}
output_directory=$(dirname -- "$output_file")
module_cache="${TMPDIR:-/tmp}/bearwarden-swift-module-cache"
codesign_identity=${CODESIGN_IDENTITY:--}
build_architecture=${MACOS_AUTOFILL_ARCHITECTURE:-universal}

if [ "${BEARWARDEN_REQUIRE_SIGNED_AUTOFILL:-0}" = "1" ] && [ "$codesign_identity" = "-" ]; then
  echo "A non-ad-hoc CODESIGN_IDENTITY is required for release autofill builds." >&2
  exit 78
fi

mkdir -p "$output_directory"
mkdir -p "$module_cache"

compile() {
  architecture=$1
  destination=$2

  CLANG_MODULE_CACHE_PATH="$module_cache" \
  SWIFT_MODULECACHE_PATH="$module_cache" \
  xcrun --sdk macosx swiftc \
    -O \
    -whole-module-optimization \
    -parse-as-library \
    -target "$architecture-apple-macos12.0" \
    -framework AppKit \
    -framework ApplicationServices \
    -framework Security \
    "$source_file" \
    -o "$destination"
}

case "$build_architecture" in
  universal)
    temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/bearwarden-autofill-build.XXXXXX")
    trap 'rm -rf -- "$temporary_directory"' EXIT HUP INT TERM
    compile arm64 "$temporary_directory/helper-arm64"
    compile x86_64 "$temporary_directory/helper-x86_64"
    xcrun lipo -create \
      "$temporary_directory/helper-arm64" \
      "$temporary_directory/helper-x86_64" \
      -output "$output_file"
    ;;
  native)
    compile "$(uname -m)" "$output_file"
    ;;
  arm64|x86_64)
    compile "$build_architecture" "$output_file"
    ;;
  *)
    echo "Unsupported MACOS_AUTOFILL_ARCHITECTURE: $build_architecture" >&2
    exit 64
    ;;
esac

chmod 0755 "$output_file"
codesign --force --sign "$codesign_identity" "$output_file"

echo "Built macOS autofill helper: $output_file"
