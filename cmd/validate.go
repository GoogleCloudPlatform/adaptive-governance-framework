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
	"log"
	"strings"

	"github.com/spf13/cobra"
)

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		detectorsDir := "detectors"
		terraformDir := "build/postures"

		// Retrieve the values of the flags
		terraformOnly, _ := cmd.Flags().GetBool("terraform")
		policiesOnly, _ := cmd.Flags().GetBool("policies")

		// Determine which functions to run based on the flags
		runTerraform := false
		runPoliciesAndMetadata := false

		if terraformOnly && policiesOnly {
			// If both -t and -m are specified, run both
			runTerraform = true
			runPoliciesAndMetadata = true
		} else if terraformOnly {
			// If only -t (--terraform) is specified, run only BuildTerraform
			runTerraform = true
			fmt.Println("--terraform flag detected. Running ValidateTerraform only.")
		} else if policiesOnly {
			// If only -m (--mappings) is specified, run only GeneratePolicyMappings
			runPoliciesAndMetadata = true
			fmt.Println("--mappings flag detected. Running ValidatePolicyData only.")
		} else {
			// If no flags (or neither -t nor -m) are specified, run both (default behavior)
			runTerraform = true
			runPoliciesAndMetadata = true
			fmt.Println("No specific build flags detected. Running both ValidateTerraform and ValidatePolicyData.")
		}

		// Execute the functions based on the flags
		if runTerraform {
			terraformErrs := validateTerraform(terraformDir)
			if len(terraformErrs) > 0 {
				panic(strings.Join(terraformErrs, "\n"))
			} else {
				fmt.Println("Terraform security posture files are valid.")
			}
		}
		if runPoliciesAndMetadata {
			policyErrs := validatePolicyData(detectorsDir)
			if policyErrs != nil {
				log.Fatalf("[Error] Policy and metadata validation exited with errors: %v", policyErrs)
			} else {
				fmt.Println("All policies and associated metadata are valid.")
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)

	// Flags for validate separation
	validateCmd.Flags().BoolP("terraform", "t", false, "only validate Terraform postures")
	validateCmd.Flags().BoolP("policies", "p", false, "only validate policy definitions and metadata")
}
