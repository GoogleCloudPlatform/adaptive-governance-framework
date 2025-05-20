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
	"path/filepath"

	"gopkg.in/yaml.v2"
)

func validatePolicyData(detectorsDir string) error {
	detectorTypes, err := os.ReadDir(detectorsDir)
	if err != nil {
		return fmt.Errorf("failed to read detectors directory: %w", err)
	}

	for _, detectorTypeInfo := range detectorTypes {
		if detectorTypeInfo.IsDir() {
			detectorType := detectorTypeInfo.Name()
			detectorTypeDir := filepath.Join(detectorsDir, detectorType)
			policyNames, err := os.ReadDir(detectorTypeDir)
			if err != nil {
				return fmt.Errorf("failed to read detector type directory: %w", err)
			}
			for _, policyNameInfo := range policyNames {
				if policyNameInfo.IsDir() {
					policyName := policyNameInfo.Name()
					policyDir := filepath.Join(detectorTypeDir, policyName)
					metadataFile := filepath.Join(policyDir, "metadata.yaml")
					policyFile := filepath.Join(policyDir, "policy.yaml")

					if !validateDetectorMetadata(metadataFile) {
						fmt.Printf("Error in detector metadata: %s\n", metadataFile)
						return fmt.Errorf("detector metadata validation failed for %s", metadataFile)
					}
					err = validateDetectorPolicy(policyFile, detectorType)
					if err != nil {
						fmt.Printf("Error in detector policy: %s, Type: %s, Error: %v\n", policyFile, detectorType, err)
						return fmt.Errorf("detector policy validation failed for %s: %w", policyFile, err)
					}
				}
			}
		}
	}
	return nil
}

func validateDetectorPolicy(policyFile string, detectorType string) error {
	data, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("failed to read policy file %s: %w", policyFile, err)
	}

	var policyData Policy
	err = yaml.Unmarshal(data, &policyData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal YAML file %s: %w", policyFile, err)
	}

	errorsFound := false

	// Access constraint data through the struct
	constraintData := policyData.Constraint

	//switch statement
	switch detectorType {
	case "sha":
		if constraintData.SHAModule == nil {
			fmt.Printf("Error: Invalid policy data in %s. Expected SHA module, found nil\n", policyFile)
			return fmt.Errorf("invalid policy data")
		}
		if !validateShaPolicy(constraintData.SHAModule, policyFile) {
			errorsFound = true
		}
	case "customsha":
		if constraintData.CustomSHAModule == nil {
			fmt.Printf("Error: Invalid policy data in %s. Expected Custom SHA module, found nil\n", policyFile)
			return fmt.Errorf("invalid policy data")
		}
		if !validateCustomShaPolicy(constraintData.CustomSHAModule, policyFile) {
			errorsFound = true
		}
	case "orgpolicy":
		if constraintData.OrgPolicyConstraint == nil {
			fmt.Printf("Error: Invalid policy data in %s. Expected Org Policy Constraint, found nil\n", policyFile)
			return fmt.Errorf("invalid policy data")
		}
		if !validateOrgPolicy(constraintData.OrgPolicyConstraint, policyFile) {
			errorsFound = true
		}
	case "customorgpolicy":
		if constraintData.CustomOrgPolicyConstraint == nil {
			fmt.Printf("Error: Invalid policy data in %s. Expected Custom Org Policy Constraint, found nil\n", policyFile)
			return fmt.Errorf("invalid policy data")
		}
		if !validateCustomOrgPolicy(constraintData.CustomOrgPolicyConstraint, policyFile) {
			errorsFound = true
		}
	default:
		fmt.Printf(
			"Error: Unknown detector type: %s in %s\n", detectorType, policyFile)
		return fmt.Errorf("unknown detector type")
	}

	if errorsFound {
		return fmt.Errorf("policy validation failed")
	}
	return nil
}

func validateShaPolicy(shaModule *SHAModule, policyFile string) bool {
	errorsFound := false
	if shaModule == nil {
		fmt.Printf("Error: SHA Module is nil in %s\n", policyFile)
		return false
	}
	if shaModule.ModuleName == "" {
		fmt.Printf("Error: ModuleName is empty in %s\n", policyFile)
		errorsFound = true
	}
	if shaModule.ModuleEnablementState == "" {
		fmt.Printf("Error: ModuleEnablementState is empty in %s\n", policyFile)
		errorsFound = true
	}
	return !errorsFound
}

func validateCustomShaPolicy(customSHAModule *CustomSHAModule, policyFile string) bool {
	errorsFound := false
	if customSHAModule == nil {
		fmt.Printf("Error: Custom SHA Module is nil in %s\n", policyFile)
		return false
	}
	if customSHAModule.DisplayName == "" {
		fmt.Printf("Error: DisplayName is empty in %s\n", policyFile)
		errorsFound = true
	}
	if customSHAModule.ModuleEnablementState == "" {
		fmt.Printf("Error: ModuleEnablementState is empty in %s\n", policyFile)
		errorsFound = true
	}
	return !errorsFound
}

func validateOrgPolicy(orgPolicyConstraint *OrgPolicyConstraint, policyFile string) bool {
	errorsFound := false
	if orgPolicyConstraint == nil {
		fmt.Printf("Error: OrgPolicyConstraint is nil in %s\n", policyFile)
		return false
	}
	if orgPolicyConstraint.CannedConstraintID == "" {
		fmt.Printf("Error: CannedConstraintID is empty in %s\n", policyFile)
		errorsFound = true
	}
	for _, rule := range orgPolicyConstraint.PolicyRules {
		if rule.DenyAll && rule.AllowAll {
			fmt.Printf("Error: denyAll and allowAll cannot both be true in %s\n", policyFile)
			errorsFound = true
		}
		if rule.ListPolicy != nil {
			if len(rule.ListPolicy.AllowedValues) > 0 && len(rule.ListPolicy.DeniedValues) > 0 {
				fmt.Printf("Error: allowedValues and deniedValues cannot both be present in %s\n", policyFile)
				errorsFound = true
			}
		}
		// TODO: Add more validations for the fields in OrgPolicyConstraint
	}
	return !errorsFound
}

func validateCustomOrgPolicy(customOrgPolicyConstraint *CustomOrgPolicyConstraint, policyFile string) bool {
	errorsFound := false
	if customOrgPolicyConstraint == nil {
		fmt.Printf("Error: CustomOrgPolicyConstraint is nil in %s\n", policyFile)
		return false
	}
	if customOrgPolicyConstraint.CustomConstraint.Name == "" {
		fmt.Printf("Error: CustomConstraint Name is empty in %s\n", policyFile)
		errorsFound = true
	}
	if customOrgPolicyConstraint.CustomConstraint.DisplayName == "" {
		fmt.Printf("Error: CustomConstraint DisplayName is empty in %s\n", policyFile)
		errorsFound = true
	}
	if customOrgPolicyConstraint.CustomConstraint.Description == "" {
		fmt.Printf("Error: CustomConstraint Description is empty in %s\n", policyFile)
		errorsFound = true
	}
	if customOrgPolicyConstraint.CustomConstraint.ActionType == "" {
		fmt.Printf("Error: CustomConstraint ActionType is empty in %s\n", policyFile)
		errorsFound = true
	}
	if customOrgPolicyConstraint.CustomConstraint.Condition == "" {
		fmt.Printf("Error: CustomConstraint Condition is empty in %s\n", policyFile)
		errorsFound = true
	}
	if len(customOrgPolicyConstraint.CustomConstraint.MethodTypes) == 0 {
		fmt.Printf("Error: CustomConstraint MethodTypes is empty in %s\n", policyFile)
		errorsFound = true
	}
	if len(customOrgPolicyConstraint.CustomConstraint.ResourceTypes) == 0 {
		fmt.Printf("Error: CustomConstraint ResourceTypes is empty in %s\n", policyFile)
		errorsFound = true
	}
	for _, rule := range customOrgPolicyConstraint.PolicyRules {
		if rule.Condition != nil {
			if rule.Condition.Description == "" {
				fmt.Printf("Error: Rule Condition Description is empty in %s\n", policyFile)
				errorsFound = true
			}
			if rule.Condition.Expression == "" {
				fmt.Printf("Error: Rule Condition Expression is empty in %s\n", policyFile)
				errorsFound = true
			}
			if rule.Condition.Title == "" {
				fmt.Printf("Error: Rule Condition Title is empty in %s\n", policyFile)
				errorsFound = true
			}
		}
	}
	return !errorsFound
}
