#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "Skipping macOS autofill helper on $(uname -s)"
  exit 0
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(dirname -- "$script_directory")
source_file="$project_root/native/macos-autofill/main.swift"
info_template="$project_root/native/macos-autofill/Info.plist"
icon_file="$project_root/build/icon.icns"
bundle_directory=${1:-"$project_root/resources/bin/BearWarden Autofill Helper.app"}
case "$bundle_directory" in
  *.app) ;;
  *)
    echo "The macOS autofill helper output must be an .app bundle." >&2
    exit 64
    ;;
esac
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/bearwarden-autofill-build.XXXXXX")
trap 'rm -rf -- "$temporary_directory"' EXIT HUP INT TERM
staging_bundle="$temporary_directory/BearWarden Autofill Helper.app"
contents_directory="$staging_bundle/Contents"
output_directory="$contents_directory/MacOS"
resources_directory="$contents_directory/Resources"
output_file="$output_directory/bearwarden-macos-autofill"
module_cache="${TMPDIR:-/tmp}/bearwarden-swift-module-cache"
codesign_identity=${CODESIGN_IDENTITY:--}
build_architecture=${MACOS_AUTOFILL_ARCHITECTURE:-universal}
package_version=$(node -p 'require(process.argv[1]).version' "$project_root/package.json")
bundle_version=$(printf '%s' "$package_version" | sed 's/[^0-9.].*$//')

if [ -z "$bundle_version" ]; then
  bundle_version=1
fi

if [ "${BEARWARDEN_REQUIRE_SIGNED_AUTOFILL:-0}" = "1" ] && [ "$codesign_identity" = "-" ]; then
  echo "A non-ad-hoc CODESIGN_IDENTITY is required for release autofill builds." >&2
  exit 78
fi

mkdir -p "$output_directory" "$resources_directory"
mkdir -p "$module_cache"
cp "$info_template" "$contents_directory/Info.plist"
cp "$icon_file" "$resources_directory/icon.icns"
plutil -replace CFBundleShortVersionString -string "$bundle_version" "$contents_directory/Info.plist"
plutil -replace CFBundleVersion -string "$bundle_version" "$contents_directory/Info.plist"

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
if [ "$codesign_identity" = "-" ]; then
  codesign --force --sign - "$staging_bundle"
else
  codesign --force --options runtime --timestamp --sign "$codesign_identity" "$staging_bundle"
fi
plutil -lint "$contents_directory/Info.plist" >/dev/null
codesign --verify --strict --verbose=2 "$staging_bundle"

mkdir -p "$(dirname -- "$bundle_directory")"
rm -rf -- "$bundle_directory"
mv "$staging_bundle" "$bundle_directory"

echo "Built macOS autofill helper: $bundle_directory"
