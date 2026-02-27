#!/bin/bash

set -e  # Exit on errors
set -o pipefail  # Fail pipeline if any command fails

# iOS Targets only (device only)
IOS_ARCHS=("aarch64-apple-ios")

# Variables
CRATE_NAME="clash-ffi"
LIB_NAME="clashrs"
OUTPUT_DIR="build"

HEADERS_DIR="${OUTPUT_DIR}/Headers"
HEADER_FILE="${HEADERS_DIR}/${LIB_NAME}/${LIB_NAME}.h"
MODULEMAP_FILE="${HEADERS_DIR}/${LIB_NAME}/module.modulemap"
XCFRAMEWORK_DIR="${OUTPUT_DIR}/${LIB_NAME}.xcframework"

# Build profile: release (default) or debug
BUILD_PROFILE="${1:-release}"
case "$BUILD_PROFILE" in
    release)
        CARGO_PROFILE_FLAG="--release"
        TARGET_PROFILE_DIR="release"
        ;;
    debug)
        CARGO_PROFILE_FLAG=""
        TARGET_PROFILE_DIR="debug"
        ;;
    *)
        echo "Usage: $0 [release|debug]"
        exit 1
        ;;
esac

echo "Build profile: $BUILD_PROFILE"

# Ensure the toolchain from rust-toolchain.toml is installed and switched
echo "Ensuring the Rust toolchain from rust-toolchain.toml is installed..."
if [ -f "rust-toolchain.toml" ]; then
    TOOLCHAIN=$(grep -E 'channel\s*=' rust-toolchain.toml | cut -d'"' -f2)
    if ! rustup show active-toolchain &> /dev/null; then
        rustup install "$TOOLCHAIN"
    fi
else
    echo "Error: rust-toolchain.toml not found. Please ensure it exists in the project directory."
    exit 1
fi

echo "Using toolchain: $TOOLCHAIN"

# Install necessary Rust targets
echo "Installing necessary Rust targets..."
for target in "${IOS_ARCHS[@]}"; do
    rustup target add "$target" --toolchain "$TOOLCHAIN" || echo "Target $target may need local stdlib build."
done

# Ensure necessary tools are installed
echo "Checking for required tools..."
if ! command -v cbindgen &> /dev/null; then
    echo "Installing cbindgen..."
    cargo +"$TOOLCHAIN" install cbindgen
fi

# Create output directories
mkdir -p "$OUTPUT_DIR"
mkdir -p "$HEADERS_DIR/$LIB_NAME"

# Build static libraries for iOS targets (workspace build, like build_apple.sh)
echo "Building library for iOS targets..."
for target in "${IOS_ARCHS[@]}"; do
    export IPHONEOS_DEPLOYMENT_TARGET=13.0
    cargo +"$TOOLCHAIN" build --target "$target" $CARGO_PROFILE_FLAG
    mkdir -p "$OUTPUT_DIR/$target"
    cp "target/$target/$TARGET_PROFILE_DIR/lib${LIB_NAME}.a" "$OUTPUT_DIR/$target/"
done

# Generate C header file using cbindgen
echo "Generating C header file..."
cbindgen --config "$CRATE_NAME/cbindgen.toml" --crate "$CRATE_NAME" --output "$HEADER_FILE"

echo "Creating modulemap..."
cat > "$MODULEMAP_FILE" <<EOF
module $LIB_NAME {
    umbrella header "$(basename "$HEADER_FILE")"
    export *
}
EOF

# Create XCFramework (iOS device only)
echo "Creating iOS device-only XCFramework..."
rm -rf "$XCFRAMEWORK_DIR"
xcodebuild -create-xcframework \
    -library "$OUTPUT_DIR/aarch64-apple-ios/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
    -output "$XCFRAMEWORK_DIR"

echo "XCFramework created at $XCFRAMEWORK_DIR"

# Cleanup intermediate per-arch libraries, keep XCFramework and headers
echo "Cleaning up intermediate per-arch libraries..."
find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 ! -name "$(basename "$XCFRAMEWORK_DIR")" ! -name "$(basename "$HEADERS_DIR")" -exec rm -rf {} +

echo "Done!"
