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
	"regexp"

	"gopkg.in/yaml.v2"
)

func validateDetectorMetadata(metadataFile string) bool {
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		fmt.Printf("Error reading detector metadata file: %s, error: %v\n", metadataFile, err)
		return false
	}

	var metadata Metadata
	err = yaml.Unmarshal(data, &metadata)
	if err != nil {
		fmt.Printf("Error unmarshalling detector metadata file: %s, error: %v\n", metadataFile, err)
		return false
	}

	errorsFound := false

	// Begin by validating that all the required keys are present for Rego metadata
	if metadata.PolicyID == "" {
		fmt.Printf("Error: Missing PolicyId in detector metadata file: %s\n", metadataFile)
		errorsFound = true
	}
	if metadata.Description == "" {
		fmt.Printf("Error: Missing Description in detector metadata file: %s\n", metadataFile)
		errorsFound = true
	}
	if len(metadata.Postures) == 0 {
		fmt.Printf("Error: Missing Postures in detector metadata file: %s\n", metadataFile)
		errorsFound = true
	}
	if metadata.Author == "" {
		fmt.Printf("Error: Missing Author in Rego metadata file: %s\n", metadataFile)
		errorsFound = true
	}

	// If there are issues with validation at this stage (missing keys), return now
	if errorsFound {
		return !errorsFound
	}

	// Validate policyId format
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-_]{0,62}$`).MatchString(metadata.PolicyID) {
		fmt.Printf(
			"Error: Invalid policyId format in %s. Must match '^[a-zA-Z][a-zA-Z0-9-_]{0,62}$'\n", metadataFile)
		errorsFound = true
	}

	return !errorsFound
}
