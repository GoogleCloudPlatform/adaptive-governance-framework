#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Shared script to download, cache, and execute a specific version of the AGF CLI.
# Works for both local pre-commit and GitHub Actions composite action.

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Disabled temporarily for initial version check
# Exit status of the last command that threw a non-zero exit code is returned.
set -o pipefail

# --- Configuration and Input ---
CLI_VERSION="$1"
if [ -z "$CLI_VERSION" ]; then
    echo "[ERROR] CLI version argument not provided to run-agf.sh."
    exit 1
fi
shift # Remove the version from the arguments list, rest are passed to the CLI

set -u # Re-enable strict unset variable checking

CLI_NAME="agf"

# Determine environment and set variables accordingly
if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
    # Running in GitHub Actions
    echo "[INFO] Running in GitHub Actions environment."
    REPO_OWNER_AND_NAME="${GITHUB_REPOSITORY}" # Use the action's context
    # Use runner's temporary directory for caching in Actions
    LOCAL_BIN_ROOT="${RUNNER_TEMP:-/tmp}/agf-bin-cache" # RUNNER_TEMP is usually set, fallback to /tmp
else
    # Running locally (e.g., pre-commit)
    echo "[INFO] Running in local environment."
    # Use GITHUB_REPOSITORY if set (e.g., by act), otherwise fallback.
    # WARNING: Fallback is hardcoded, might need adjustment if repo name changes or for forks.
    REPO_OWNER_AND_NAME="${GITHUB_REPOSITORY:-GoogleCloudPlatform/adaptive-governance-framework}"
    # Use local .bin directory for caching locally (ensure .bin/ is in .gitignore)
    LOCAL_BIN_ROOT=".bin"
    echo "[INFO] Using repository: ${REPO_OWNER_AND_NAME}"
    echo "[INFO] Using local cache: ${LOCAL_BIN_ROOT}"
fi

TARGET_DIR="${LOCAL_BIN_ROOT}/${CLI_NAME}/${CLI_VERSION}"
mkdir -p "${TARGET_DIR}" # Ensure cache directory exists

# --- Determine Platform ---
OS_RAW="$(uname -s | tr '[:upper:]' '[:lower:]')" # Get raw OS string
OS="${OS_RAW}"                                    # Default OS to the raw output

# Normalize OS name for Windows environments as GoReleaser uses 'windows'
if [[ "$OS_RAW" == "windows_nt" || "$OS_RAW" == "mingw"* || "$OS_RAW" == "msys"* || "$OS_RAW" == "cygwin"* ]]; then
    OS="windows"
    echo "[INFO] Normalized OS to 'windows' from '${OS_RAW}'"
elif [[ "$OS_RAW" == "darwin" ]]; then
    OS="darwin" # Already correct
elif [[ "$OS_RAW" == "linux" ]]; then
    OS="linux" # Already correct
else
    echo "[WARN] Unrecognized OS_RAW: '${OS_RAW}'. Using it directly. This might cause issues if it doesn't match GoReleaser asset names."
fi

ARCH_RAW="$(uname -m)"
ARCH="${ARCH_RAW}" # Default ARCH to raw output
case "$ARCH_RAW" in
x86_64) ARCH="amd64" ;;
aarch64) ARCH="arm64" ;;
arm64) ARCH="arm64" ;; # For macOS arm
*)
    echo "[ERROR] Unsupported architecture: $ARCH_RAW"
    exit 1
    ;;
esac

BINARY_FILENAME="${CLI_NAME}"
ARCHIVE_EXTENSION="tar.gz"
if [ "$OS" == "windows" ]; then
    BINARY_FILENAME="${CLI_NAME}.exe"
    ARCHIVE_EXTENSION="zip"
fi

EXPECTED_BINARY_PATH="${TARGET_DIR}/${BINARY_FILENAME}"

# --- Construct Download URL ---
# Assumes GoReleaser creates assets WITHOUT 'v' prefix in filename (e.g., agf_0.1.0...)
# but the tag/version used in the URL itself DOES have 'v' (e.g., .../download/v0.1.0/...)
VERSION_NO_V="${CLI_VERSION#v}"                              # Removes 'v' prefix if present for filename generation
ARCHIVE_BASENAME="${CLI_NAME}_${VERSION_NO_V}_${OS}_${ARCH}" # Use the potentially normalized $OS
DOWNLOAD_ARCHIVE_NAME="${ARCHIVE_BASENAME}.${ARCHIVE_EXTENSION}"
DOWNLOAD_URL="https://github.com/${REPO_OWNER_AND_NAME}/releases/download/${CLI_VERSION}/${DOWNLOAD_ARCHIVE_NAME}"

# --- Download and Extract if Needed ---
if [ ! -f "$EXPECTED_BINARY_PATH" ]; then
    echo "[INFO] Downloading ${CLI_NAME} ${CLI_VERSION} for ${OS}/${ARCH} from ${DOWNLOAD_URL}..."
    TEMP_DOWNLOAD_FILE=$(mktemp)
    # Use -L to follow redirects, --fail to exit on HTTP error, -sS for silent+show errors
    if curl -sSL --fail --show-error "$DOWNLOAD_URL" -o "$TEMP_DOWNLOAD_FILE"; then
        echo "[INFO] Extracting ${DOWNLOAD_ARCHIVE_NAME} to ${TARGET_DIR}..."
        if [ "$ARCHIVE_EXTENSION" == "zip" ]; then
            # Use unzip for .zip files (Windows)
            unzip -q -o "$TEMP_DOWNLOAD_FILE" "${BINARY_FILENAME}" -d "$TARGET_DIR"
        else # .tar.gz for Linux/macOS
            # Use tar for .tar.gz files
            tar -xzf "$TEMP_DOWNLOAD_FILE" -C "$TARGET_DIR" "${BINARY_FILENAME}"
        fi
        rm "$TEMP_DOWNLOAD_FILE"         # Clean up temp download file
        chmod +x "$EXPECTED_BINARY_PATH" # chmod might fail harmlessly on Windows for .exe
        echo "[INFO] ${CLI_NAME} installed to ${EXPECTED_BINARY_PATH}"
    else
        echo "[ERROR] Failed to download ${CLI_NAME} from ${DOWNLOAD_URL}. Check URL and asset existence."
        rm -f "$TEMP_DOWNLOAD_FILE" # Clean up failed download
        # If repo is private or release is draft, download will fail without auth.
        if [[ "${GITHUB_ACTIONS:-false}" != "true" ]]; then
            echo "[HINT] If the repository is private or the release is a draft, direct download might fail locally."
            echo "[HINT] Consider installing AGF manually via 'go install' or downloading from releases."
        fi
        exit 1
    fi
else
    echo "[INFO] ${CLI_NAME} version ${CLI_VERSION} found in cache: ${EXPECTED_BINARY_PATH}"
fi

# --- Add to PATH (GitHub Actions Only) ---
if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
    echo "[INFO] Adding $(dirname "$EXPECTED_BINARY_PATH") to GITHUB_PATH for subsequent steps."
    echo "$(dirname "$EXPECTED_BINARY_PATH")" >>$GITHUB_PATH
fi

# --- Execute the Binary ---
echo "[INFO] Executing: ${EXPECTED_BINARY_PATH} $@"
"$EXPECTED_BINARY_PATH" "$@"

exit 0 # Success
