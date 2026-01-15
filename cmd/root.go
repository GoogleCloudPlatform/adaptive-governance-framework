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

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Package-level variables to store version info passed from main
var (
	appVersion string
	appCommit  string
	appDate    string
)

var rootCmd = &cobra.Command{
	Use:   "agf",
	Short: "AGF CLI - A tool for managing policies and postures",
	Long: `AGF (Adaptive Governance Framework) is a CLI tool
to help you manage cloud security and compliance policies declaratively.`,
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Adaptive Governance Framework (AGF) version information.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Print the version information using the package-level variables
		effectiveVersion := appVersion
		if effectiveVersion == "" {
			effectiveVersion = "dev" // Default if not injected
		}
		effectiveCommit := appCommit
		if effectiveCommit == "" {
			effectiveCommit = "none"
		}
		effectiveDate := appDate
		if effectiveDate == "" {
			effectiveDate = "unknown"
		}

		fmt.Printf("agf version %s\n", effectiveVersion)
		fmt.Printf("commit: %s\n", effectiveCommit)
		fmt.Printf("built at: %s\n", effectiveDate)
	},
}

// Execute is the primary entry point for running the CLI from the main package.
// It accepts version, commit, and date strings (sourced from ldflags in main.go),
// stores them for use by the version command, and then executes the root command.
func Execute(versionFromMain, commitFromMain, dateFromMain string) {
	appVersion = versionFromMain
	appCommit = commitFromMain
	appDate = dateFromMain
	
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
