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
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"gopkg.in/yaml.v2"
)

// PostureData represents the posture data extracted from Terraform
type PostureData struct {
	Name     string       `json:"name"`
	Policies []PolicyJson `json:"policies"`
	Posture  string       `json:"posture"`
}

// Policy represents a single policy with its ID and description
type PolicyJson struct {
	PolicyID    string `json:"policy_id"`
	Description string `json:"description"`
}

func extractImplementsData(policyDef *yaml.MapSlice, policyType string) (string, error) {
	constraint := getFromMapSlice(*policyDef, "constraint")
	if constraint == nil {
		return "", fmt.Errorf("'constraint' key not found in policy definition")
	}

	constraintMap, ok := constraint.(yaml.MapSlice)
	if !ok {
		// Handle potential map[interface{}]interface{} type from yaml parser
		if _, okMap := constraint.(map[interface{}]interface{}); okMap {
			return "", fmt.Errorf("constraint data format is map[interface{}]interface{}, expected yaml.MapSlice")
		}
		return "", fmt.Errorf("constraint is not a yaml.MapSlice (type: %T)", constraint)
	}

	switch policyType {
	case "sha":
		securityHealthAnalyticsModule := getFromMapSlice(constraintMap, "securityHealthAnalyticsModule")
		if securityHealthAnalyticsModule == nil {
			return "", fmt.Errorf("securityHealthAnalyticsModule not found in constraint")
		}
		shaMap, ok := securityHealthAnalyticsModule.(yaml.MapSlice)
		if !ok {
			return "", fmt.Errorf("securityHealthAnalyticsModule is not a yaml.MapSlice")
		}

		moduleName := getFromMapSlice(shaMap, "moduleName")
		if moduleName == nil {
			return "", fmt.Errorf("moduleName not found in securityHealthAnalyticsModule")
		}
		nameStr, ok := moduleName.(string)
		if !ok {
			return "", fmt.Errorf("moduleName is not a string")
		}
		return "SHA Module: " + nameStr, nil

	case "customsha":
		securityHealthAnalyticsCustomModule := getFromMapSlice(constraintMap, "securityHealthAnalyticsCustomModule")
		if securityHealthAnalyticsCustomModule == nil {
			return "", fmt.Errorf("securityHealthAnalyticsCustomModule not found in constraint")
		}
		customShaMap, ok := securityHealthAnalyticsCustomModule.(yaml.MapSlice)
		if !ok {
			return "", fmt.Errorf("securityHealthAnalyticsCustomModule is not a yaml.MapSlice")
		}

		customConstraint := getFromMapSlice(customShaMap, "config")
		if customConstraint == nil {
			return "", fmt.Errorf("config not found in securityHealthAnalyticsCustomModule")
		}
		// The config itself might be the data we want to marshal
		customConstraintYAML, err := yaml.Marshal(customConstraint)
		if err != nil {
			return "", fmt.Errorf("failed to marshal customConstraint config: %w", err)
		}
		return string(customConstraintYAML), nil

	case "orgpolicy":
		orgPolicyConstraint := getFromMapSlice(constraintMap, "orgPolicyConstraint")
		if orgPolicyConstraint == nil {
			return "", fmt.Errorf("orgPolicyConstraint not found in constraint")
		}
		orgMap, ok := orgPolicyConstraint.(yaml.MapSlice)
		if !ok {
			return "", fmt.Errorf("orgPolicyConstraint is not a yaml.MapSlice")
		}

		cannedConstraintId := getFromMapSlice(orgMap, "cannedConstraintId")
		if cannedConstraintId == nil {
			return "", fmt.Errorf("cannedConstraintId not found in orgPolicyConstraint")
		}
		idStr, ok := cannedConstraintId.(string)
		if !ok {
			return "", fmt.Errorf("cannedConstraintId is not a string")
		}
		return "Organization Policy: " + idStr, nil

	case "customorgpolicy":
		orgPolicyConstraintCustom := getFromMapSlice(constraintMap, "orgPolicyConstraintCustom")
		if orgPolicyConstraintCustom == nil {
			return "", fmt.Errorf("orgPolicyConstraintCustom not found in constraint")
		}
		customOrgMap, ok := orgPolicyConstraintCustom.(yaml.MapSlice)
		if !ok {
			return "", fmt.Errorf("orgPolicyConstraintCustom is not a yaml.MapSlice")
		}

		customConstraint := getFromMapSlice(customOrgMap, "customConstraint")
		if customConstraint == nil {
			return "", fmt.Errorf("customConstraint not found in orgPolicyConstraintCustom")
		}
		// Marshal the customConstraint block
		customConstraintYAML, err := yaml.Marshal(customConstraint)
		if err != nil {
			return "", fmt.Errorf("failed to marshal customConstraint: %w", err)
		}
		return string(customConstraintYAML), nil

	default:
		return "", fmt.Errorf("unsupported policy type: %s", policyType)
	}
}

func loadPolicyMetadata(detectorsDir string) (map[string]*Metadata, error) {
	allMetadata := make(map[string]*Metadata)

	// Load detector policy metadata using the global variable
	err := filepathWalk(detectorsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Use info from WalkFunc which is os.FileInfo
		if !info.IsDir() && filepath.Ext(path) == ".yaml" && info.Name() == "metadata.yaml" {
			metadataFile := path
			policyDir := filepath.Dir(metadataFile) // Path to the directory containing metadata.yaml
			policyID := filepath.Base(policyDir)    // Extract policy ID

			// Parse metadata.yaml (ensure extractMetadata uses mocked readFile)
			metadata, err := extractMetadata(metadataFile)
			if err != nil {
				// Wrap error with more context and continue walking if desired, or return to stop.
				// Returning error stops the walk.
				return fmt.Errorf("error processing metadata %s: %w", metadataFile, err)
			}

			// Determine policy type based on directory structure relative to detectorsDir
			relativePathToPolicyDir, err := filepath.Rel(detectorsDir, policyDir)
			if err != nil {
				return fmt.Errorf("error determining relative path for %s from %s: %w", policyDir, detectorsDir, err)
			}

			pathComponents := strings.Split(relativePathToPolicyDir, string(filepath.Separator))
			if len(pathComponents) < 1 {
				return fmt.Errorf("policy directory structure under %s is unexpected for path %s (relative: %s)", detectorsDir, policyDir, relativePathToPolicyDir)
			}
			policyType := pathComponents[0]

			// Read the detector policy definition (ensure loadYAML uses mocked readFile)
			policyFile := filepath.Join(policyDir, "policy.yaml")
			policyDef, err := loadYAML(policyFile)
			if err != nil {
				// Return error to stop the walk if policy file is essential
				return fmt.Errorf("error loading policy file %s: %w", policyFile, err)
			}

			// Extract "Implements" data
			implementsData, err := extractImplementsData(policyDef, policyType)
			if err != nil {
				// Return error to stop the walk
				return fmt.Errorf("error extracting 'implements' data for policy %s (type %s): %w", policyID, policyType, err)
			}
			metadata.Implements = implementsData

			// Store policy type and location without filename
			metadata.PolicyType = policyType
			metadata.Location = policyDir
			allMetadata[policyID] = metadata
		}
		return nil
	})
	if err != nil {
		// This error is from the walk itself or an error returned by the walkFn
		return nil, fmt.Errorf("failed to walk detectors directory: %w", err)
	}

	return allMetadata, nil
}

func loadYAML(file string) (*yaml.MapSlice, error) {
	// Use the global variable readFile
	data, err := osReadFile(file)
	if err != nil {
		return nil, err
	}

	var ms yaml.MapSlice
	err = yaml.Unmarshal(data, &ms)
	if err != nil {
		return nil, err
	}

	return &ms, nil
}

func getFromMapSlice(ms yaml.MapSlice, key string) interface{} {
	for _, item := range ms {
		if item.Key == key {
			return item.Value
		}
	}
	return nil
}

func getTerraformPostureData(terraformDir string) (map[string][]*PostureData, error) {
	postureData := make(map[string][]*PostureData)

	// Use the mocked filepathWalk
	err := filepathWalk(terraformDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Error accessing path (permissions, etc.)
			return fmt.Errorf("error accessing path %q during walk: %w", path, err)
		}

		// We only care about files with .tf extension
		if !info.IsDir() && filepath.Ext(path) == ".tf" {
			// Read Terraform file contents using the global variable
			file, err := osReadFile(path)
			if err != nil {
				// Return error to stop the walk
				return fmt.Errorf("failed to read Terraform file %s: %w", path, err)
			}

			// Parse the Terraform file
			hclFile, diags := hclwrite.ParseConfig(file, path, hcl.InitialPos)
			if diags.HasErrors() {
				// Join the errors into a single string
				errStrings := []string{}
				for _, diagErr := range diags.Errs() { // Renamed loop variable
					errStrings = append(errStrings, diagErr.Error())
				}
				// Return error to stop the walk
				return fmt.Errorf("failed to parse Terraform file %s: %s", path, strings.Join(errStrings, ", "))
			}

			// Extract posture data
			for _, block := range hclFile.Body().Blocks() {
				if block.Type() == "resource" && len(block.Labels()) > 0 && block.Labels()[0] == "google_securityposture_posture" {
					// Use info.Name() which comes from the walk function
					postureName := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
					posture := PostureData{Name: postureName, Posture: postureName}

					// Extract policy IDs and descriptions
					for _, policySetBlock := range block.Body().Blocks() {
						if policySetBlock.Type() == "policy_sets" {
							for _, policyBlock := range policySetBlock.Body().Blocks() {
								if policyBlock.Type() == "policies" {
									policyID := getAttribute(policyBlock, "policy_id")
									description := getAttribute(policyBlock, "description")
									posture.Policies = append(posture.Policies, PolicyJson{PolicyID: policyID, Description: description})
								}
							}
						}
					}

					// Add posture data to the map
					postureData[postureName] = append(postureData[postureName], &posture)
				}
			}
		}
		return nil // Continue walking
	})
	if err != nil {
		// This error is from the walk itself or an error returned by the walkFn
		return nil, fmt.Errorf("failed during Terraform directory walk (%s): %w", terraformDir, err)
	}

	return postureData, nil
}

func getAttribute(block *hclwrite.Block, attribute string) string {
	attr := block.Body().GetAttribute(attribute)
	if attr != nil {
		return tokensToString(attr.Expr().BuildTokens(nil))
	}
	return ""
}

func generatePolicyMappings(postureData map[string][]*PostureData, allMetadata map[string]*Metadata, mappingsDir string) error {

	// Create the mappings directory if it doesn't exist using the global variable
	err := osMkdirAll(mappingsDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create mappings directory %s: %w", mappingsDir, err)
	}

	// Generate CSV files for each posture
	for postureName, postures := range postureData {
		csvFilePath := filepath.Join(mappingsDir, fmt.Sprintf("%s_mappings.csv", postureName))
		fmt.Printf("[Info] Writing mappings to '%s_mappings.csv' ...\n", postureName)

		// Create the CSV file using the global variable
		csvFile, err := osCreateFile(csvFilePath)
		if err != nil {
			return fmt.Errorf("failed to create CSV file %s: %w", csvFilePath, err)
		}

		// --- Corrected File Closing and Flushing ---
		// Use a local variable for the file to ensure Close is called correctly.
		f := csvFile
		defer f.Close() // Ensure file is closed eventually

		// Create a CSV writer
		writer := csv.NewWriter(f) // Write to the file handle

		// Write the CSV header
		header := []string{"Policy Type", "Location", "Policy ID", "Description", "Postures", "Author", "Compliance Standards", "Implements"}
		err = writer.Write(header)
		if err != nil {
			// f.Close() // Close explicitly on error before returning
			return fmt.Errorf("failed to write CSV header to %s: %w", csvFilePath, err)
		}

		// Collect policy data for this posture
		uniquePolicyData := make(map[string]*Metadata)
		for _, posture := range postures {
			for _, policy := range posture.Policies {
				if metadata, ok := allMetadata[policy.PolicyID]; ok {
					if _, exists := uniquePolicyData[metadata.PolicyID]; !exists {
						uniquePolicyData[metadata.PolicyID] = metadata
					}
				}
			}
		}

		policyData := make([]*Metadata, 0, len(uniquePolicyData))
		for _, meta := range uniquePolicyData {
			policyData = append(policyData, meta)
		}

		sort.Slice(policyData, func(i, j int) bool {
			if policyData[i].PolicyType != policyData[j].PolicyType {
				return policyData[i].PolicyType < policyData[j].PolicyType
			}
			return policyData[i].PolicyID < policyData[j].PolicyID
		})

		// Write policy data to CSV
		for _, data := range policyData {
			complianceStandardsStr := ""
			// String representation of compliance standards map
			for i, std := range data.ComplianceStandards {
				if std.Standard != "" {
					if i > 0 {
						complianceStandardsStr += "; "
					}
					complianceStandardsStr += fmt.Sprintf("%s :: %s", std.Standard, std.Control)
				}
			}

			// Create string representation of postures each policy lands in
			sort.Strings(data.Postures)
			posturesStr := strings.Join(data.Postures, ", ")

			record := []string{
				data.PolicyType, data.Location, data.PolicyID, data.Description,
				posturesStr, data.Author, complianceStandardsStr, data.Implements,
			}
			err := writer.Write(record)
			if err != nil {
				// f.Close() // Close explicitly on error before returning
				return fmt.Errorf("failed to write record to CSV %s: %w", csvFilePath, err)
			}
		}

		// Explicitly flush the writer BEFORE closing the file
		writer.Flush()
		err = writer.Error() // Check for any error during flush
		if err != nil {
			// f.Close() // Close explicitly on error before returning
			return fmt.Errorf("error flushing CSV writer for %s: %w", csvFilePath, err)
		}

		// Now close the file (deferred close will also run, but explicit is fine)
		err = f.Close()
		if err != nil {
			fmt.Printf("[Warning] Failed to close CSV file %s after writing: %v\n", csvFilePath, err)
		}

	}

	// Delete stale posture mapping CSVs if there are any
	existingPostures := make(map[string]bool)
	for postureName := range postureData {
		existingPostures[postureName] = true
	}

	err = filepathWalk(mappingsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), "_mappings.csv") {
			postureName := strings.TrimSuffix(info.Name(), "_mappings.csv")
			if _, ok := existingPostures[postureName]; !ok {
				err := osRemoveFile(path) // Use mocked removeFile
				if err != nil {
					fmt.Printf("[Warning] Failed to delete stale CSV file %s: %v\n", path, err)
				} else {
					fmt.Printf("[Info] Deleted stale posture mapping CSV: %s\n", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed during stale CSV cleanup walk in %s: %w", mappingsDir, err)
	}

	return nil
}

func GeneratePolicyMappings() {
	terraformDir := "build/postures"
	detectorsDir := "detectors"
	mappingsDir := "build/mappings"

	// 1. Load policy metadata from YAML files
	allMetadata, err := loadPolicyMetadata(detectorsDir)
	if err != nil {
		fmt.Println("Error loading policy metadata:", err)
		return
	}

	// 2. Extract posture data from Terraform postures
	postureData, err := getTerraformPostureData(terraformDir)
	if err != nil {
		fmt.Println("Error extracting posture data:", err)
		return
	}

	// 3. Generate policy mappings based on postureData and allMetadata
	err = generatePolicyMappings(postureData, allMetadata, mappingsDir)
	if err != nil {
		fmt.Println("Error generating policy mappings:", err)
		return
	}

	fmt.Println("[Info] Successfully updated posture mappings.")
}
