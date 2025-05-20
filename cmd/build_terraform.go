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
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v2"
)

func normalizePolicyID(policyID string) string {
	// Trim leading/trailing spaces and replace internal spaces with underscores
	return strings.ReplaceAll(strings.TrimSpace(policyID), " ", "_")
}

func getTerraformFiles(terraformDir string) []string {
	var terraformFiles []string
	files, err := osReadDir(terraformDir)
	if err != nil {
		log.Fatalf("Failed to read Terraform directory: %v", err)
	}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".tf") {
			terraformFiles = append(terraformFiles, file.Name())
		}
	}
	return terraformFiles
}

func sortPolicyTypes(policies map[string]map[string]*Policy) []string {
	policyTypes := make([]string, 0, len(policies))
	for policyType := range policies {
		policyTypes = append(policyTypes, policyType)
	}
	sort.Strings(policyTypes)
	return policyTypes
}

func sortPolicies(policies map[string]*Policy) []*Policy {
	sortedPolicies := make([]*Policy, 0, len(policies))
	for _, policy := range policies {
		sortedPolicies = append(sortedPolicies, policy)
	}
	sort.Slice(sortedPolicies, func(i, j int) bool {
		return sortedPolicies[i].PolicyID < sortedPolicies[j].PolicyID
	})
	return sortedPolicies
}

func createStringVals(inputStrings []string) []cty.Value {
	// If the input slice is nil or has a length of 0 (empty)
	if len(inputStrings) == 0 {
		// Return an empty, but importantly, NON-NIL slice of cty.Value.
		// This is what cty.ListVal expects for empty lists.
		return make([]cty.Value, 0)
	}

	// For non-empty input, create the slice of cty.Values
	// Initialize with make and capacity for efficiency
	values := make([]cty.Value, 0, len(inputStrings))
	for _, s := range inputStrings {
		values = append(values, cty.StringVal(s))
	}
	return values
}

func updateTerraform(terraformDir string, policies map[string]map[string]*Policy, allMetadata map[string]*Metadata) error {
	for _, terraformFile := range getTerraformFiles(terraformDir) {
		terraformFilePath := filepath.Join(terraformDir, terraformFile)
		file, err := osReadFile(terraformFilePath)
		if err != nil {
			return fmt.Errorf("failed to read Terraform file %s: %w", terraformFilePath, err)
		}

		// Parse the Terraform file
		terraformData, diags := hclwrite.ParseConfig(file, terraformFilePath, hcl.Pos{})
		if diags.HasErrors() {
			return fmt.Errorf("failed to parse Terraform file %s: %s", terraformFilePath, diags.Error())
		}

		// Find the google_securityposture_posture resource
		var resource *hclwrite.Block
		for _, block := range terraformData.Body().Blocks() {
			if block.Type() == "resource" && len(block.Labels()) > 0 && block.Labels()[0] == "google_securityposture_posture" {
				resource = block
				break
			}
		}
		if resource == nil {
			return fmt.Errorf("no 'google_securityposture_posture' resource found in %s", terraformFilePath)
		}

		// Collect unique postures for each policy type
		uniquePostures := make(map[string]map[string]struct{})
		for policyType, typePolicies := range policies {
			uniquePostures[policyType] = make(map[string]struct{})
			for _, policy := range typePolicies {
				// Retrieve metadata, handling potential missing entries
				metadata, ok := allMetadata[policy.PolicyID]
				if !ok {
					return fmt.Errorf("metadata not found for policy ID: %s", policy.PolicyID)
				}

				postures := metadata.Postures // Access postures from the retrieved metadata
				for _, posture := range postures {
					uniquePostures[policyType][posture] = struct{}{}
				}
			}
		}

		// Remove any policy sets that are not in the allowed list
		validPolicySetIDs := map[string]bool{
			"customorgpolicy_policy_set": true,
			"customsha_policy_set":       true,
			"orgpolicy_policy_set":       true,
			"sha_policy_set":             true,
		}
		for _, block := range resource.Body().Blocks() {
			if block.Type() == "policy_sets" {
				policySet := block
				policySetIdAttribute := policySet.Body().GetAttribute("policy_set_id")
				if policySetIdAttribute != nil {
					policySetID := tokensToString(policySetIdAttribute.Expr().BuildTokens(nil))
					if !validPolicySetIDs[policySetID] {
						resource.Body().RemoveBlock(policySet)
					}
				} else {
					resource.Body().RemoveBlock(policySet)
				}
			}
		}

		// Iterate through policy types and update/create policy sets
		for _, policyType := range sortPolicyTypes(policies) { // Iterate over policy types
			policySetID := fmt.Sprintf("%s_policy_set", policyType)
			var updatedPolicySet *hclwrite.Block

			// Find the existing policy set
			for _, block := range resource.Body().Blocks() {
				if block.Type() == "policy_sets" {
					ps := block
					if tokensToString(ps.Body().GetAttribute("policy_set_id").Expr().BuildTokens(nil)) == policySetID {
						updatedPolicySet = ps
						// Remove existing policies within the policy set
						var policiesToRemove []*hclwrite.Block
						for _, policyBlock := range updatedPolicySet.Body().Blocks() {
							if policyBlock.Type() == "policies" {
								policiesToRemove = append(policiesToRemove, policyBlock)
							}
						}
						for _, blockToRemove := range policiesToRemove {
							updatedPolicySet.Body().RemoveBlock(blockToRemove)
						}
						break
					}
				}
			}

			fmt.Printf("Processing %s policies for %s:\n", policyType, terraformFile[:len(terraformFile)-3])

			for _, policy := range sortPolicies(policies[policyType]) {
				metadata, ok := allMetadata[policy.PolicyID] // Use PolicyID to retrieve metadata
				if !ok {
					return fmt.Errorf("metadata not found for policy ID: %s", policy.PolicyID)
				}

				// Check if the current Terraform file is listed in the policy's postures
				if slices.Contains(metadata.Postures, terraformFile[:len(terraformFile)-3]) {
					fmt.Printf(" - Found %s in metadata, adding %s\n", terraformFile[:len(terraformFile)-3], policy.PolicyID)

					if updatedPolicySet == nil {
						// Create a new policy set if it doesn't exist
						updatedPolicySet = hclwrite.NewBlock("policy_sets", nil)
						updatedPolicySet.Body().SetAttributeValue("policy_set_id", cty.StringVal(policySetID))
						updatedPolicySet.Body().SetAttributeValue("description", cty.StringVal(fmt.Sprintf("::DO NOT EDIT::Policy Set for only %s policies, auto-inlined from repository.", policyType)))
						resource.Body().AppendBlock(updatedPolicySet)
					}

					newPolicyBlock, err := createNewPolicyBlock(policy, metadata, policyType)
					if err != nil {
						return fmt.Errorf("failed to create policy block: %w", err)
					}
					// Append the inner 'policies' block to the 'updatedPolicySet'
					for _, block := range newPolicyBlock.Body().Blocks() {
						if block.Type() == "policies" {
							updatedPolicySet.Body().AppendBlock(block)
							fmt.Printf("   - %s \t (from %s)\n", policy.PolicyID, metadata.PolicyFileName)
							break // Assuming only one 'policies' block per 'newPolicyBlock'
						}
					}
				}
			}
		}

		// Write the updated Terraform code back to the file
		err = osWriteFile(terraformFilePath, terraformData.Bytes(), 0644)
		if err != nil {
			return fmt.Errorf("failed to write Terraform file %s: %w", terraformFilePath, err)
		}
	}
	return nil
}

func BuildTerraform() {
	detectorsDir := "detectors"
	terraformDir := "build/postures"

	// Initialize maps to store policies and metadata
	policies := make(map[string]map[string]*Policy)
	allMetadata := make(map[string]*Metadata)

	// Walk the detectors directory
	err := filepathWalk(detectorsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only process policy.yaml files
		if !info.IsDir() && info.Name() == "policy.yaml" {
			policyFile := path
			metadataFile := filepath.Join(filepath.Dir(path), "metadata.yaml")

			// Determine policy type based on directory structure
			policyType := strings.Split(filepath.Dir(policyFile), "/")[1]

			// Parse metadata.yaml
			metadata, err := extractMetadata(metadataFile)
			if err != nil {
				return fmt.Errorf("failed to extract metadata from %s: %w", metadataFile, err)
			}

			// Parse policy.yaml
			policyData, err := osReadFile(policyFile)
			if err != nil {
				return fmt.Errorf("failed to read policy file %s: %w", policyFile, err)
			}

			// Parse policy.yaml
			var policy Policy
			err = yaml.Unmarshal(policyData, &policy)
			if err != nil {
				return fmt.Errorf("failed to parse policy file %s: %w", policyFile, err)
			}

			// Normalize policy.PolicyID to match metadata.Name format
			policy.PolicyID = normalizePolicyID(policy.PolicyID) // Normalize the ID

			// Ensure policy.PolicyID matches metadata.PolicyID (this is still needed)
			policy.PolicyID = metadata.PolicyID

			// Get the Filename for logging/debugging purposes
			metadata.PolicyFileName = filepath.Dir(path)

			// Store policy and metadata
			if _, ok := policies[policyType]; !ok {
				policies[policyType] = make(map[string]*Policy)
			}

			policy.MetadataName = metadata.PolicyID // Set MetadataName before storing the policy
			policies[policyType][metadata.PolicyID] = &policy
			allMetadata[metadata.PolicyID] = metadata
		}

		return nil
	})
	if err != nil {
		log.Fatalf("Failed to walk detectors directory: %v", err)
	}

	// Update Terraform files
	err = updateTerraform(terraformDir, policies, allMetadata)
	if err != nil {
		log.Fatalf("Failed to update Terraform files: %v", err)
	}
}
