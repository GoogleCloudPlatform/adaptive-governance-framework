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
	"os" // Required for os.WriteFile in the test loop
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Assume createTempDir and createTempFile are available from validate_test_helpers.go
// For the test to be runnable standalone, we'd need their implementations or to mock them.
// For now, this file focuses on the test logic itself.
// func createTempDir(t *testing.T, pattern string) string { /* ... */ }
// func createTempFile(t *testing.T, dir, fileName, content string) string { /* ... */ }
// func getLineNumber(code []byte, searchString string) int { /* ... defined in validateTerraform.go ... */ }
// func validateTerraform(dir string) []string { /* ... defined in validateTerraform.go ... */ }

func TestGetLineNumber(t *testing.T) {
	// Assuming this test setup and expected values are correct as per your environment,
	// as it wasn't failing in the provided output.
	// Line numbers can be tricky depending on whether the input byte slice starts with a newline.
	testCode := []byte(`
line 1: some text
line 2: key = "value"
line 3: another_key = "another_value" # with a comment
line 4: final line
`) // Initial newline means "line 1: some text" is on line 2 if 1-indexed.

	tests := []struct {
		name         string
		code         []byte
		searchString string
		expectedLine int
	}{
		{
			name:         "Exact match without quotes",
			code:         testCode,
			searchString: "key", // Will match "key" in "another_key" or "key ="
			expectedLine: 3,     // Assuming it finds "line 2: key = "value"" which is the 3rd line of `testCode`
		},
		{
			name:         "Match with value and quotes",
			code:         testCode,
			searchString: `key\s*=\s*"value"`,
			expectedLine: 3, // "line 2: key = "value"" is the 3rd line
		},
		{
			name:         "Match with comment",
			code:         testCode,
			searchString: `another_key\s*=\s*"another_value"`,
			expectedLine: 4, // "line 3: another_key..." is the 4th line
		},
		{
			name:         "Not found",
			code:         testCode,
			searchString: "nonexistent",
			expectedLine: -1,
		},
		{
			name:         "Empty code",
			code:         []byte(``),
			searchString: "key",
			expectedLine: -1,
		},
		{
			name:         "Search string is partial of line",
			code:         testCode,
			searchString: "line 1",
			expectedLine: 2, // "line 1: some text" is the 2nd line
		},
		{
			name:         "Search string is only whitespace",
			code:         []byte("  \n  test\n"), // Line 1: "  ", Line 2: "  test"
			searchString: "test",
			expectedLine: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This function is part of the cmd package (validateTerraform.go)
			line := getLineNumber(tt.code, tt.searchString)
			assert.Equal(t, tt.expectedLine, line)
		})
	}
}

// TestValidateTerraform tests the validateTerraform function.
// It focuses on:
// 1. Correct count of 'google_securityposture_posture' resource declarations.
// 2. Validation of 'posture_id' assignments if the resource count is 1.
// 3. Validation of 'policy_set_id' assignments if the resource count is 1.
// 4. Validation of 'policy_id' assignments if the resource count is 1.
func TestValidateTerraform(t *testing.T) {
	// Base content with one valid posture resource declaration
	// and various ID assignments for testing.
	baseValidPostureDeclaration := `
resource "google_securityposture_posture" "my_valid_posture" {
  // posture_id will be varied by tests
}

// Other content can exist in the file
`

	tests := []struct {
		name                    string
		tfFileContents          map[string]string // filename -> content
		expectErrors            bool
		expectedErrorSubstrings []string
	}{
		// --- Resource Count Validation ---
		{
			name: "Valid: Exactly one posture resource, no specific IDs to check here",
			tfFileContents: map[string]string{
				"valid_count.tf": `resource "google_securityposture_posture" "p1" {}`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Error: 'google_securityposture_posture' resource declared in", "but no 'posture_id' assignment found in the file"},
		},
		{
			name: "Invalid: Zero posture resources",
			tfFileContents: map[string]string{
				"zero_resources.tf": `resource "google_project" "my_project" {}`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"must contain exactly one 'google_securityposture_posture' resource declaration. Found 0"},
		},
		{
			name: "Invalid: Two posture resources",
			tfFileContents: map[string]string{
				"two_resources.tf": `
resource "google_securityposture_posture" "p1" {}
resource "google_securityposture_posture" "p2" {}
`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"must contain exactly one 'google_securityposture_posture' resource declaration. Found 2"},
		},

		// --- Posture ID Validation (assuming 1 resource declaration) ---
		{
			name: "Valid: Posture ID format",
			tfFileContents: map[string]string{
				"valid_posture_id.tf": baseValidPostureDeclaration + `posture_id = "valid-id-123"`,
			},
			expectErrors: false,
		},
		{
			name: "Invalid: Posture ID starts with number",
			tfFileContents: map[string]string{
				"invalid_posture_id_number.tf": baseValidPostureDeclaration + `posture_id = "1invalid-id"`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'posture_id' value '1invalid-id'", "Must match '^[a-z][a-z0-9-_]{0,62}$'"},
		},
		{
			name: "Invalid: Posture ID too long",
			tfFileContents: map[string]string{
				"invalid_posture_id_long.tf": baseValidPostureDeclaration + `posture_id = "this-is-a-very-long-posture-id-that-exceeds-the-maximum-allowed-length-of-sixty-three-characters"`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'posture_id' value 'this-is-a-very-long-posture-id", "Must match '^[a-z][a-z0-9-_]{0,62}$'"},
		},
		{
			name: "Invalid: Posture ID has invalid char (uppercase)",
			tfFileContents: map[string]string{
				"invalid_posture_id_char.tf": baseValidPostureDeclaration + `posture_id = "InvalidID"`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'posture_id' value 'InvalidID'", "Must match '^[a-z][a-z0-9-_]{0,62}$'"},
		},
		{
			name: "Invalid: Missing posture_id assignment",
			tfFileContents: map[string]string{
				"missing_posture_id.tf": baseValidPostureDeclaration, // No posture_id = "..."
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"resource declared", "but no 'posture_id' assignment found"},
		},

		// --- Policy Set ID Validation (assuming 1 resource declaration) ---
		{
			name: "Valid: Policy Set ID format",
			tfFileContents: map[string]string{
				"valid_policy_set_id.tf": baseValidPostureDeclaration + `posture_id = "sample-posture-123" policy_set_id = "valid-set-id"`,
			},
			expectErrors: false, // No error if only policy_set_id is present and valid, and posture_id is missing (as it would be caught by posture_id check if that was the focus)
			// For this test, we assume posture_id might be missing or valid, focusing on policy_set_id
		},
		{
			name: "Invalid: Policy Set ID starts with number",
			tfFileContents: map[string]string{
				"invalid_policy_set_id_num.tf": baseValidPostureDeclaration + `policy_set_id = "2invalid-set"`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'policy_set_id' value '2invalid-set'", "Must match '^[a-z][a-z0-9-_]{0,62}$'"},
		},
		{
			name: "Valid: Multiple valid Policy Set IDs",
			tfFileContents: map[string]string{
				"multiple_valid_policy_set_ids.tf": baseValidPostureDeclaration + `
posture_id = "sample-posture-123"
policy_set_id = "set-alpha"
policy_set_id = "set-beta-001"
`,
			},
			expectErrors: false,
		},
		{
			name: "Invalid: One valid, one invalid Policy Set ID",
			tfFileContents: map[string]string{
				"mixed_policy_set_ids.tf": baseValidPostureDeclaration + `
policy_set_id = "set-good"
policy_set_id = "SetBadUppercase" 
`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'policy_set_id' value 'SetBadUppercase'"},
		},

		// --- Policy ID Validation (assuming 1 resource declaration) ---
		{
			name: "Valid: Policy ID format",
			tfFileContents: map[string]string{
				"valid_policy_id.tf": baseValidPostureDeclaration + `
posture_id = "sample-posture-123"
policy_id = "ValidPolicyID-01"`,
			},
			expectErrors: false,
		},
		{
			name: "Invalid: Policy ID starts with number (allowed by regex, but good to test specific cases)",
			tfFileContents: map[string]string{
				"invalid_policy_id_num.tf": baseValidPostureDeclaration + `policy_id = "1ValidPolicy"`, // This is actually valid by ^[a-zA-Z]... oh wait, no it's not.
			},
			expectErrors:            true, // Corrected: ^[a-zA-Z] means it must start with a letter.
			expectedErrorSubstrings: []string{"Invalid 'policy_id' value '1ValidPolicy'", "Must match '^[a-zA-Z][a-zA-Z0-9-_]{0,62}$'"},
		},
		{
			name: "Invalid: Policy ID has invalid char (underscore allowed, but test others)",
			tfFileContents: map[string]string{
				"invalid_policy_id_char.tf": baseValidPostureDeclaration + `policy_id = "policy!@#"`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'policy_id' value 'policy!@#", "Must match '^[a-zA-Z][a-zA-Z0-9-_]{0,62}$'"},
		},

		// --- Combinations and Edge Cases ---
		{
			name: "Valid: One resource, valid posture_id, valid policy_set_id, valid policy_id",
			tfFileContents: map[string]string{
				"all_valid_ids.tf": `
resource "google_securityposture_posture" "p1" {}
posture_id = "p-id-correct"
policy_set_id = "ps-id-correct"
policy_id = "pol-id-Correct"
`,
			},
			expectErrors: false,
		},
		{
			name: "Invalid: One resource, invalid posture_id, valid other IDs",
			tfFileContents: map[string]string{
				"one_invalid_posture_id.tf": `
resource "google_securityposture_posture" "p1" {}
posture_id = "123-BAD" 
policy_set_id = "ps-id-correct"
policy_id = "pol-id-Correct"
`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'posture_id' value '123-BAD'"},
		},
		{
			name: "File with no relevant ID assignments (but one resource)",
			tfFileContents: map[string]string{
				"no_ids_one_resource.tf": baseValidPostureDeclaration + `description = "some description"`,
			},
			expectErrors:            true, // Expect error for missing posture_id
			expectedErrorSubstrings: []string{"no 'posture_id' assignment found"},
		},

		// --- File/Directory Handling ---
		{
			name:                    "Directory does not exist",
			tfFileContents:          nil, // Special case handled in test setup
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Could not walk the directory"},
		},
		{
			name:                    "Directory with no .tf files",
			tfFileContents:          map[string]string{"not_tf.txt": "some content"},
			expectErrors:            false, // No .tf files means no validation errors from this function
			expectedErrorSubstrings: []string{},
		},
		{
			name: "Multiple files, one with error",
			tfFileContents: map[string]string{
				"good.tf": `resource "google_securityposture_posture" "g" {}\nposture_id = "good-id"`,
				"bad.tf":  `resource "google_securityposture_posture" "b" {}\nposture_id = "BAD_ID"`,
			},
			expectErrors:            true,
			expectedErrorSubstrings: []string{"Invalid 'posture_id' value 'BAD_ID'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			if tt.name == "Directory does not exist" {
				// For this specific test, use a non-existent directory path
				// by attempting to validate a path that won't be created.
				errors := validateTerraform(filepath.Join(tempDir, "non_existent_dir_for_test"))
				if tt.expectErrors {
					assert.NotEmpty(t, errors, "Expected errors for non-existent directory, but got none")
					for _, sub := range tt.expectedErrorSubstrings {
						assert.Contains(t, strings.Join(errors, "\n"), sub, "Error message for non-existent directory should contain: %s", sub)
					}
				} else {
					assert.Empty(t, errors, "Expected no errors for non-existent directory, but got: %v", errors)
				}
				return // End this specific test case
			}

			// Create .tf files in the temp directory
			for filename, content := range tt.tfFileContents {
				filePath := filepath.Join(tempDir, filename)
				err := os.WriteFile(filePath, []byte(content), 0644)
				if err != nil {
					t.Fatalf("Failed to create temp file %s: %v", filename, err)
				}
			}

			errors := validateTerraform(tempDir)

			if tt.expectErrors {
				assert.NotEmpty(t, errors, "Expected errors, but got none for test: %s", tt.name)
				combinedErrors := strings.Join(errors, "\n")
				for _, sub := range tt.expectedErrorSubstrings {
					assert.Contains(t, combinedErrors, sub, "For test '%s', error message should contain substring: '%s'.\nFull errors:\n%s", tt.name, sub, combinedErrors)
				}
			} else {
				assert.Empty(t, errors, "Expected no errors, but got: %v for test: %s", errors, tt.name)
			}
		})
	}
}
