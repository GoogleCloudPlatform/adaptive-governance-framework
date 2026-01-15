// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "github.com/tdesrosi/agf-googlestaging-clone/cmd"

// These variables are populated by the Go linker (`ldflags`) during the build process.
// The `-X` flag targets variables in the 'main' package.
var (
	Version string // Default will be empty, GoReleaser injects like "0.1.0"
	Commit  string // Default will be empty, GoReleaser injects commit SHA
	Date    string // Default will be empty, GoReleaser injects build date
)

func main() {
	// Pass the version information (populated by ldflags) into the cmd package.
	// Assumes cmd package has an ExecuteVersionInfo function or similar mechanism.
	cmd.Execute(Version, Commit, Date)
}
