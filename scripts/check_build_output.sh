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

# Pre-commit hook script to run 'agf build' and check for unstaged changes
# in specified output directories.

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Temporarily disable to handle potentially unset AGF_VERSION gracefully initially
# Exit status of the last command that threw a non-zero exit code is returned.
set -o pipefail

# --- Configuration ---
AGF_VERSION="$1"                      # Expect version passed as the first argument
RUN_AGF_SCRIPT="./scripts/run_agf.sh" # Path to the script that runs AGF
OUTPUT_DIRS=(
  "build/postures"
  "mappings"
)

# --- Helper Functions ---
info() {
  echo "[INFO] $(date +'%T') $1"
}

error_exit() {
  echo "[ERROR] $(date +'%T') $1" >&2
  exit 1
}

# --- Sanity Checks ---
if [[ -z "$AGF_VERSION" ]]; then
  error_exit "AGF version was not provided as the first argument to this script."
fi
set -u # Re-enable strict unset variable checking

if [[ ! -x "$RUN_AGF_SCRIPT" ]]; then
  error_exit "Helper script '$RUN_AGF_SCRIPT' not found or not executable."
fi

# --- Run 'agf build' using the helper script ---
info "Running 'agf build' using version ${AGF_VERSION}..."

# Execute 'agf build' via the helper script. Capture output/errors if needed.
# Pass the version first, then the 'build' command.
if ! "$RUN_AGF_SCRIPT" "$AGF_VERSION" build; then
  error_exit "'agf build' command failed. Check output above."
fi

info "Finished running 'agf build'."

# --- Check for Unstaged Changes in Output Directories ---
info "Checking if generated files match staged/committed state in output directories..."

# Build the list of paths for git status, ensuring they exist
output_paths_string=""
paths_to_check=()
for dir in "${OUTPUT_DIRS[@]}"; do
  if [[ -d "$dir" ]]; then
    paths_to_check+=("$dir")
    output_paths_string+=" $dir" # For logging
  else
    info "Output directory '$dir' does not exist, skipping check for it."
  fi
done
# Trim leading/trailing spaces for logging
output_paths_string=$(echo "$output_paths_string" | awk '{$1=$1};1')

if [[ ${#paths_to_check[@]} -eq 0 ]]; then
  info "No existing output directories specified to check. Skipping git status check."
  exit 0 # Nothing to check, technically success
fi

info "Checking status of directories: $output_paths_string"

# Use git status --porcelain <paths...> to check for modifications (' M') or untracked ('??') files
# ONLY within the specified output directories.
# Grep for lines starting with space+M (modified tracked) or ?? (untracked)
# Note: We check specifically for tracked file modifications or *new* untracked files.
# If a file was deleted by 'agf build' but is still staged, git status might show ' D'.
# If a file was deleted by 'agf build' and *not* staged, it won't show in status porcelain.
# This check primarily catches cases where build *changed* or *added* files that aren't staged.
if git status --porcelain "${paths_to_check[@]}" | grep -E -q "^( M|\?\?)"; then
  echo "[VALIDATION FAILED] 'agf build' resulted in changes within tracked directories that are not staged." >&2
  echo "This likely means source files were modified but 'agf build' wasn't run and its output committed." >&2
  echo "'agf build' has been run by this hook. Please review the changes below:" >&2
  echo "----------------------------------" >&2
  # Show the specific unstaged/untracked files for clarity
  git status --porcelain "${paths_to_check[@]}" | grep -E "^( M|\?\?)" >&2
  echo "----------------------------------" >&2
  echo "To fix: Use 'git add ${paths_to_check[*]}' to stage the correct generated files, then try committing again." >&2
  exit 1 # Fail the pre-commit hook
else
  info "Validation successful: Output files in specified directories match the version staged for commit."
fi

exit 0 # Success
