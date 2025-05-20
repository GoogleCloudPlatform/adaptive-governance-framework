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

	"github.com/spf13/cobra"
)

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build Terraform postures and generate mappings",
	Long: `Build (agf build) will inline your detector policies into the
appropriate Terraform resources, as determined by policy metadata.

It will also generate or regenerate the policy mapping information present
in your 'mappings/' directory`,
	Run: func(cmd *cobra.Command, args []string) {
		// Retrieve the values of the flags
		// The GetBool method returns the flag's value and an error, which we ignore here with '_'
		// as we've defined these flags and expect them to exist.
		terraformOnly, _ := cmd.Flags().GetBool("terraform")
		mappingsOnly, _ := cmd.Flags().GetBool("mappings")

		// Determine which functions to run based on the flags
		runTerraform := false
		runMappings := false

		if terraformOnly && mappingsOnly {
			// If both -t and -m are specified, run both
			runTerraform = true
			runMappings = true
		} else if terraformOnly {
			// If only -t (--terraform) is specified, run only BuildTerraform
			runTerraform = true
			fmt.Println("--terraform flag detected. Running BuildTerraform only.")
		} else if mappingsOnly {
			// If only -m (--mappings) is specified, run only GeneratePolicyMappings
			runMappings = true
			fmt.Println("--mappings flag detected. Running GeneratePolicyMappings only.")
		} else {
			// If no flags (or neither -t nor -m) are specified, run both (default behavior)
			runTerraform = true
			runMappings = true
			fmt.Println("No specific build flags detected. Running both BuildTerraform and GeneratePolicyMappings.")
		}

		// Execute the functions based on the flags
		if runTerraform {
			BuildTerraform()
		}
		if runMappings {
			GeneratePolicyMappings()
		}
	},
}

func init() {
	rootCmd.AddCommand(buildCmd)

	// Flags for build separation
	buildCmd.Flags().BoolP("terraform", "t", false, "only build Terraform postures")
	buildCmd.Flags().BoolP("mappings", "m", false, "only generate policy mappings")
}
