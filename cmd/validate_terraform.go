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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// getLineNumber searches for a string within a byte slice representing code
// and returns the 1-based line number where the string is found.
// It uses a regular expression for matching, making the search flexible.
func getLineNumber(code []byte, searchString string) int {
	scanner := bufio.NewScanner(strings.NewReader(string(code)))
	lineNum := 1
	// searchString is expected to be a valid regex pattern.
	re, err := regexp.Compile(searchString)
	if err != nil {
		// If the search string itself is an invalid regex, return -1.
		// This could indicate an issue with how searchString is constructed by the caller.
		return -1
	}

	for scanner.Scan() {
		if re.MatchString(scanner.Text()) {
			return lineNum
		}
		lineNum++
	}
	return -1 // Return -1 if the searchString is not found
}

// validateTerraform walks through a directory, reads .tf files, and validates:
// 1. Each file contains exactly one 'google_securityposture_posture' resource declaration.
// 2. If so, it validates all found 'posture_id' values in the file.
// 3. It validates all found 'policy_set_id' values in the file.
// 4. It validates all found 'policy_id' values in the file.
// These ID validations are performed on any matching assignment pattern, regardless of HCL structure.
func validateTerraform(terraformDir string) []string {
	var errorMessages []string

	// Regex for specific ID value validations
	postureIDFormatValidation := regexp.MustCompile(`^[a-z][a-z0-9-_]{0,62}$`)
	policySetIDFormatValidation := regexp.MustCompile(`^[a-z][a-z0-9-_]{0,62}$`)
	policyIDFormatValidation := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-_]{0,62}$`)

	// Regex to extract ID values from assignments anywhere in the file
	postureIDExtractRegex := regexp.MustCompile(`posture_id\s*=\s*"(.*?)"`)
	policySetIDExtractRegex := regexp.MustCompile(`policy_set_id\s*=\s*"(.*?)"`)
	policyIDExtractRegex := regexp.MustCompile(`policy_id\s*=\s*"(.*?)"`)

	err := filepath.Walk(terraformDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // Propagate error to stop Walk if critical (e.g., dir not found)
		}
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(info.Name()), ".tf") {
			return nil // Skip directories and non-.tf files.
		}

		terraformCode, readErr := os.ReadFile(path)
		if readErr != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("Error: Could not read Terraform file: %s. Details: %v", path, readErr))
			return nil // Continue with the next file.
		}

		// 1. Validate there's only one google_securityposture_posture resource declaration
		resourceDeclarationRegex := regexp.MustCompile(`resource "google_securityposture_posture" "([^"]*)"\s*{`)
		resourceDeclarationMatches := resourceDeclarationRegex.FindAllStringIndex(string(terraformCode), -1)

		if len(resourceDeclarationMatches) != 1 {
			lineNum := -1
			if len(resourceDeclarationMatches) > 0 {
				// Get line number of the first declaration found
				firstMatchStartOffset := resourceDeclarationMatches[0][0]
				lineNum = getLineNumber(terraformCode[:firstMatchStartOffset+1], `resource "google_securityposture_posture"`) // Search up to the match
				if lineNum == -1 {                                                                                            // Fallback if specific line not found
					lineNum = getLineNumber(terraformCode, `resource "google_securityposture_posture"`)
				}
			} else {
				lineNum = 1 // Default to start of file if no resource found.
			}
			errorMessages = append(errorMessages, fmt.Sprintf("Error: File %s must contain exactly one 'google_securityposture_posture' resource declaration. Found %d. First occurrence (if any) near line ~%d.", path, len(resourceDeclarationMatches), lineNum))
			return nil // Stop processing this file if resource count is not 1.
		}

		// If exactly one resource declaration is found, proceed to validate IDs found anywhere in the file.

		// 2. Validate all 'posture_id' values found in the file
		allPostureIDAssignments := postureIDExtractRegex.FindAllStringSubmatch(string(terraformCode), -1)
		if len(allPostureIDAssignments) == 0 {
			// This could be an error if a posture_id is strictly expected within the declared resource,
			// but per simplified rules, we only validate what we find.
			// If the resource is declared, it *should* have a posture_id.
			// Let's add an error if the resource is declared but no posture_id assignment is found in the file.
			errorMessages = append(errorMessages, fmt.Sprintf("Error: 'google_securityposture_posture' resource declared in %s, but no 'posture_id' assignment found in the file.", path))
		}
		for _, match := range allPostureIDAssignments {
			postureIDValue := match[1] // The captured group (the value)
			if !postureIDFormatValidation.MatchString(postureIDValue) {
				// For line number, search for the specific assignment `posture_id = "value"`
				searchPattern := fmt.Sprintf(`posture_id\s*=\s*"%s"`, regexp.QuoteMeta(postureIDValue))
				lineNum := getLineNumber(terraformCode, searchPattern)
				errorMessages = append(errorMessages, fmt.Sprintf("Error: Invalid 'posture_id' value '%s' found in %s at line ~%d. Must match '%s'.", postureIDValue, path, lineNum, postureIDFormatValidation.String()))
			}
		}

		// 3. Validate all 'policy_set_id' values found in the file
		allPolicySetIDAssignments := policySetIDExtractRegex.FindAllStringSubmatch(string(terraformCode), -1)
		for _, match := range allPolicySetIDAssignments {
			policySetIDValue := match[1]
			if !policySetIDFormatValidation.MatchString(policySetIDValue) {
				searchPattern := fmt.Sprintf(`policy_set_id\s*=\s*"%s"`, regexp.QuoteMeta(policySetIDValue))
				lineNum := getLineNumber(terraformCode, searchPattern)
				errorMessages = append(errorMessages, fmt.Sprintf("Error: Invalid 'policy_set_id' value '%s' found in %s at line ~%d. Must match '%s'.", policySetIDValue, path, lineNum, policySetIDFormatValidation.String()))
			}
		}

		// 4. Validate all 'policy_id' values found in the file
		allPolicyIDAssignments := policyIDExtractRegex.FindAllStringSubmatch(string(terraformCode), -1)
		for _, match := range allPolicyIDAssignments {
			policyIDValue := match[1]
			if !policyIDFormatValidation.MatchString(policyIDValue) {
				searchPattern := fmt.Sprintf(`policy_id\s*=\s*"%s"`, regexp.QuoteMeta(policyIDValue))
				lineNum := getLineNumber(terraformCode, searchPattern)
				errorMessages = append(errorMessages, fmt.Sprintf("Error: Invalid 'policy_id' value '%s' found in %s at line ~%d. Must match '%s'.", policyIDValue, path, lineNum, policyIDFormatValidation.String()))
			}
		}
		return nil
	})

	if err != nil {
		errorMessages = append(errorMessages, fmt.Sprintf("Error: Could not walk the directory: %v", err))
	}

	return errorMessages
}
