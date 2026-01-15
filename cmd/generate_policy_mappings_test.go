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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TestExtractImplementsData tests the extractImplementsData function
func TestExtractImplementsData(t *testing.T) {
	tests := []struct {
		name          string
		policyDefYAML string
		policyType    string
		expected      string
		expectError   bool
		errorContains string // Optional substring to check in error message
	}{
		{
			name: "SHA policy type",
			policyDefYAML: `
constraint:
  securityHealthAnalyticsModule:
    moduleName: "SSL_NOT_ENFORCED"
`,
			policyType:  "sha",
			expected:    "SHA Module: SSL_NOT_ENFORCED",
			expectError: false,
		},
		{
			name: "Custom SHA policy type",
			policyDefYAML: `
constraint:
  securityHealthAnalyticsCustomModule:
    config:
      resource_selector:
        resource_types:
        - "storage.googleapis.com/Bucket"
      severity: "HIGH"
`,
			policyType: "customsha",
			expected: `resource_selector:
  resource_types:
  - storage.googleapis.com/Bucket
severity: HIGH`,
			expectError: false,
		},
		{
			name: "OrgPolicy policy type",
			policyDefYAML: `
constraint:
  orgPolicyConstraint:
    cannedConstraintId: "constraints/compute.disableSerialPortAccess"
`,
			policyType:  "orgpolicy",
			expected:    "Organization Policy: constraints/compute.disableSerialPortAccess",
			expectError: false,
		},
		{
			name: "Custom OrgPolicy policy type",
			policyDefYAML: `
constraint:
  orgPolicyConstraintCustom:
    customConstraint:
      action_type: "ALLOW"
      method_types:
      - "CREATE"
      resource_types:
      - "cloudresourcemanager.googleapis.com/Project"
`,
			policyType: "customorgpolicy",
			expected: `action_type: ALLOW
method_types:
- CREATE
resource_types:
- cloudresourcemanager.googleapis.com/Project`,
			expectError: false,
		},
		{
			name:          "Unsupported policy type",
			policyDefYAML: `constraint: {}`, // Need constraint key present
			policyType:    "unknown",
			expectError:   true,
			errorContains: "unsupported policy type",
		},
		{
			name: "SHA - missing moduleName",
			policyDefYAML: `
constraint:
  securityHealthAnalyticsModule:
    name: "SSL_NOT_ENFORCED" # wrong field
`,
			policyType:    "sha",
			expectError:   true,
			errorContains: "moduleName not found",
		},
		{
			name: "CustomSHA - missing config",
			policyDefYAML: `
constraint:
  securityHealthAnalyticsCustomModule:
    settings: {} # wrong field
`,
			policyType:    "customsha",
			expectError:   true,
			errorContains: "config not found",
		},
		{
			name: "OrgPolicy - missing cannedConstraintId",
			policyDefYAML: `
constraint:
  orgPolicyConstraint:
    id: "constraints/compute.disableSerialPortAccess" # wrong field
`,
			policyType:    "orgpolicy",
			expectError:   true,
			errorContains: "cannedConstraintId not found",
		},
		{
			name: "CustomOrgPolicy - missing customConstraint",
			policyDefYAML: `
constraint:
  orgPolicyConstraintCustom:
    constraint: {} # wrong field
`,
			policyType:    "customorgpolicy",
			expectError:   true,
			errorContains: "customConstraint not found",
		},
		{
			name: "Missing constraint",
			policyDefYAML: `
otherkey: value
`,
			policyType:    "sha",
			expectError:   true,
			errorContains: "'constraint' key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policyDef yaml.MapSlice
			err := yaml.Unmarshal([]byte(tt.policyDefYAML), &policyDef)
			require.NoError(t, err, "Failed to unmarshal test YAML") // Use require for fatal setup errors

			actual, err := extractImplementsData(&policyDef, tt.policyType)

			if tt.expectError {
				require.Error(t, err) // Use require if error is mandatory
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err) // Use require if no error is mandatory
				// Trim trailing newlines for consistent comparison as yaml.Marshal adds one
				assert.Equal(t, strings.TrimSpace(tt.expected), strings.TrimSpace(actual))
			}
		})
	}
}

// TestLoadPolicyMetadata tests the loadPolicyMetadata function using afero
func TestLoadPolicyMetadata(t *testing.T) {
	cleanup := setupTestEnvironment(t) // Sets up mock FS and mocks readFile, filepathWalk etc.
	defer cleanup()

	detectorsBaseDir := "mock_detectors_load" // Use a path within the mock FS

	// --- Setup Detector policy (SHA) ---
	shaPolicyDir := filepath.Join(detectorsBaseDir, "sha", "gcp_policy_sha_001")
	createMockFile(t, MockFs, filepath.Join(shaPolicyDir, "metadata.yaml"), `
policyId: gcp_policy_sha_001
description: "Test SHA Policy"
postures: ["posture_b"]
author: "tester"
complianceStandards: [{"standard": "NIST", "control": "AC-1"}]
`)
	createMockFile(t, MockFs, filepath.Join(shaPolicyDir, "policy.yaml"), `
constraint:
  securityHealthAnalyticsModule:
    moduleName: "TEST_SHA_MODULE"
`)

	// --- Setup Detector policy (OrgPolicy) ---
	orgPolicyDir := filepath.Join(detectorsBaseDir, "orgpolicy", "gcp_policy_org_001")
	createMockFile(t, MockFs, filepath.Join(orgPolicyDir, "metadata.yaml"), `
policyId: gcp_policy_org_001
description: "Test Org Policy"
postures: ["posture_c"]
author: "tester"
complianceStandards: [{"standard": "PCI", "control": "1.0"}]
`)
	createMockFile(t, MockFs, filepath.Join(orgPolicyDir, "policy.yaml"), `
constraint:
  orgPolicyConstraint:
    cannedConstraintId: "constraints/test.orgPolicy"
`)
	// --- Setup Invalid Metadata File (missing required field) ---
	invalidMetaDir := filepath.Join(detectorsBaseDir, "invalid", "invalid_meta_policy")
	createMockFile(t, MockFs, filepath.Join(invalidMetaDir, "metadata.yaml"), `
policyId: invalid_meta_policy
# description: "Missing description" - Intentionally missing
postures: ["posture_d"]
complianceStandards: [{"standard": "ISO", "control": "27001"}]
`)
	createMockFile(t, MockFs, filepath.Join(invalidMetaDir, "policy.yaml"), `constraint: {}`) // Need a dummy policy file

	// --- Setup Missing Policy File ---
	missingPolicyDir := filepath.Join(detectorsBaseDir, "sha", "missing_policy_file")
	createMockFile(t, MockFs, filepath.Join(missingPolicyDir, "metadata.yaml"), `
policyId: missing_policy_file
description: "Policy file is missing"
postures: ["posture_e"]
complianceStandards: [{"standard": "SOC2", "control": "CC1.1"}]
`)

	// loadPolicyMetadata uses the mocked filepathWalk and readFile
	_, err := loadPolicyMetadata(detectorsBaseDir)

	// We expect an error because the invalid metadata file or missing policy file should cause a failure.
	require.Error(t, err, "Expected an error due to invalid metadata or missing policy file")
	assert.Contains(t, err.Error(), "failed to walk detectors directory", "Error should originate from the walk")

	// Check specifically for one of the expected failure reasons
	isInvalidMetaError := strings.Contains(err.Error(), "invalid_meta_policy") && strings.Contains(err.Error(), "invalid metadata")
	isMissingPolicyError := strings.Contains(err.Error(), "missing_policy_file") && strings.Contains(err.Error(), "error loading policy file") // Updated check

	assert.True(t, isInvalidMetaError || isMissingPolicyError, "Error message should relate to invalid metadata or missing policy file, but got: %v", err)

	// The map might be partially populated or nil depending on when the walk stopped.
	// We don't assert its contents when an error is expected during the walk.
}

// TestGetTerraformPostureData tests the getTerraformPostureData function using afero
func TestGetTerraformPostureData(t *testing.T) {
	cleanup := setupTestEnvironment(t)
	defer cleanup()

	terraformDir := "mock_tf_postures" // Use a path within the mock FS

	// --- Setup Terraform file 1 (posture_alpha.tf) ---
	tfContent1 := `
resource "google_securityposture_posture" "posture_alpha_resource" {
  posture_id = "posture_alpha"
  parent     = "organizations/123456789012"
  state      = "ACTIVE"
  description = "This is posture alpha"

  policy_sets {
    policy_set_id = "cis-gcp-1.3.0"
    description   = "CIS GCP Foundations Benchmark v1.3.0"

    policies {
      policy_id   = "gcp_policy_001"
      description = "Description for policy 001"
      constraint {
         org_policy_constraint { # Corrected: Nested block on new line
            canned_constraint_id = "constraints/foo"
         }
      }
    }
    policies {
      policy_id   = "gcp_policy_002"
      description = "Description for policy 002"
    }
  }
}
`
	createMockFile(t, MockFs, filepath.Join(terraformDir, "posture_alpha.tf"), tfContent1)

	// --- Setup Terraform file 2 (posture_beta.tf) ---
	tfContent2 := `
resource "google_securityposture_posture" "posture_beta_resource" {
  posture_id = "posture_beta"
  policy_sets {
    policy_set_id = "another-set"
    policies {
      policy_id   = "gcp_policy_003"
      description = "Description for policy 003 in beta"
    }
  }
}
`
	createMockFile(t, MockFs, filepath.Join(terraformDir, "posture_beta.tf"), tfContent2)
	createMockFile(t, MockFs, filepath.Join(terraformDir, "other_resource.tf"), `resource "google_project" "my_project" {}`)
	createMockFile(t, MockFs, filepath.Join(terraformDir, "syntax_error.tf"), `resource "bad" "syntax" {`)

	_, err := getTerraformPostureData(terraformDir)

	// We expect an error because syntax_error.tf cannot be parsed
	require.Error(t, err, "Expected an error due to HCL parsing failure")
	// Check the error message based on the corrected getTerraformPostureData which uses filepathWalk
	assert.Contains(t, err.Error(), "failed during Terraform directory walk", "Error should originate from the walk")
	// The error might be from posture_alpha.tf OR syntax_error.tf depending on walk order.
	// Just check that it's a parsing error.
	assert.Contains(t, err.Error(), "failed to parse", "Error message should indicate parsing failure")
	// Assert that *one* of the problematic files is mentioned
	assert.True(t, strings.Contains(err.Error(), "syntax_error.tf") || strings.Contains(err.Error(), "posture_alpha.tf"), "Error should mention a problematic file")

	// --- Test successful case without error file ---
	t.Run("Successful Parse", func(t *testing.T) {
		cleanupSuccess := setupTestEnvironment(t) // Reset mocks for this subtest
		defer cleanupSuccess()
		terraformDirSuccess := "mock_tf_success"
		createMockFile(t, MockFs, filepath.Join(terraformDirSuccess, "posture_alpha.tf"), tfContent1)
		createMockFile(t, MockFs, filepath.Join(terraformDirSuccess, "posture_beta.tf"), tfContent2)
		createMockFile(t, MockFs, filepath.Join(terraformDirSuccess, "other_resource.tf"), `resource "google_project" "my_project" {}`)

		postureDataSuccess, errSuccess := getTerraformPostureData(terraformDirSuccess)
		require.NoError(t, errSuccess)
		require.NotNil(t, postureDataSuccess)

		// Assertions for posture_alpha
		alphaData, ok := postureDataSuccess["posture_alpha"]
		require.True(t, ok, "Posture 'posture_alpha' not found")
		require.Len(t, alphaData, 1, "Expected 1 posture entry for posture_alpha")
		assert.Equal(t, "posture_alpha", alphaData[0].Name)
		assert.Equal(t, "posture_alpha", alphaData[0].Posture)
		require.Len(t, alphaData[0].Policies, 2, "Expected 2 policies for posture_alpha")
		assert.ElementsMatch(t, []PolicyJson{ // Use ElementsMatch for order-insensitive comparison
			{PolicyID: "gcp_policy_001", Description: "Description for policy 001"},
			{PolicyID: "gcp_policy_002", Description: "Description for policy 002"},
		}, alphaData[0].Policies)

		// Assertions for posture_beta
		betaData, ok := postureDataSuccess["posture_beta"]
		require.True(t, ok, "Posture 'posture_beta' not found")
		require.Len(t, betaData, 1, "Expected 1 posture entry for posture_beta")
		assert.Equal(t, "posture_beta", betaData[0].Name)
		require.Len(t, betaData[0].Policies, 1, "Expected 1 policy for posture_beta")
		assert.Contains(t, betaData[0].Policies, PolicyJson{PolicyID: "gcp_policy_003", Description: "Description for policy 003 in beta"})

		assert.Len(t, postureDataSuccess, 2, "Expected data for 2 postures in total")
	})
}

// TestGeneratePolicyMappings tests the generatePolicyMappings function
func TestGeneratePolicyMappings(t *testing.T) {
	// Store original functions (since they are mocked by setupTestEnvironment for other tests)
	// Need to restore these functions for this test specifically
	originalReadFile := osReadFile
	originalCreateFile := osCreateFile
	originalMkdirAll := osMkdirAll
	originalRemoveFile := osRemoveFile
	originalFilepathWalk := filepathWalk

	// Restore real OS functions for the duration of this test
	osReadFile = os.ReadFile
	osCreateFile = os.Create
	osMkdirAll = os.MkdirAll
	osRemoveFile = os.Remove
	filepathWalk = filepath.Walk

	// Defer restoration of potentially mocked functions
	defer func() {
		osReadFile = originalReadFile
		osCreateFile = originalCreateFile
		osMkdirAll = originalMkdirAll
		osRemoveFile = originalRemoveFile
		filepathWalk = originalFilepathWalk
	}()

	// Use a real temporary directory for CSV output
	mappingsDir := t.TempDir() // Creates a real temp dir, automatically cleaned up

	// --- Mock PostureData ---
	mockPostureData := map[string][]*PostureData{
		"posture_one": {
			{Name: "posture_one", Posture: "posture_one", Policies: []PolicyJson{
				{PolicyID: "pol_A"}, {PolicyID: "pol_B"},
			}},
		},
		"posture_two": {
			{Name: "posture_two", Posture: "posture_two", Policies: []PolicyJson{
				{PolicyID: "pol_C"}, {PolicyID: "pol_A"},
			}},
		},
	}

	// --- Mock Metadata ---
	mockAllMetadata := map[string]*Metadata{
		"pol_A": {
			PolicyID: "pol_A", PolicyType: "custom", Location: "detectors/custom/pol_A",
			Description: "Desc A", Postures: []string{"posture_one", "posture_two", "global"}, Author: "Auth A",
			ComplianceStandards: []struct {
				Standard string `yaml:"standard"`
				Control  string `yaml:"control"`
			}{{"CIS", "1.1"}, {"NIST", "AC-1"}},
			Implements: "Custom Logic A",
		},
		"pol_B": {
			PolicyID: "pol_B", PolicyType: "sha", Location: "detectors/sha/pol_B",
			Description: "Desc B", Postures: []string{"posture_one"}, Author: "Auth B", Implements: "SHA: MODULE_B",
			ComplianceStandards: []struct {
				Standard string `yaml:"standard"`
				Control  string `yaml:"control"`
			}{},
		},
		"pol_C": {
			PolicyID: "pol_C", PolicyType: "orgpolicy", Location: "detectors/orgpolicy/pol_C",
			Description: "Desc C", Postures: []string{"posture_two"}, Author: "Auth C",
			Implements: "OrgPolicy: constraints/C",
			ComplianceStandards: []struct {
				Standard string `yaml:"standard"`
				Control  string `yaml:"control"`
			}{{"PCI", "1.0"}},
		},
	}

	// Create a stale CSV to test deletion
	staleCsvPath := filepath.Join(mappingsDir, "stale_posture_mappings.csv")
	err := os.WriteFile(staleCsvPath, []byte("header1,header2\ndata1,data2"), 0644)
	require.NoError(t, err, "Failed to create real stale CSV file")
	_, err = os.Stat(staleCsvPath)
	require.NoError(t, err, "Stale CSV should exist before generation")

	err = generatePolicyMappings(mockPostureData, mockAllMetadata, mappingsDir)
	require.NoError(t, err)

	csvPathOne := filepath.Join(mappingsDir, "posture_one_mappings.csv")
	_, err = os.Stat(csvPathOne) // Check existence on real FS
	require.NoError(t, err, "CSV file for posture_one should exist")

	fileOne, err := os.Open(csvPathOne) // Open real file
	require.NoError(t, err)
	defer fileOne.Close()

	readerOne := csv.NewReader(fileOne)
	recordsOne, err := readerOne.ReadAll()
	require.NoError(t, err)

	expectedHeader := []string{"Policy Type", "Location", "Policy ID", "Description", "Postures", "Author", "Compliance Standards", "Implements"}
	require.Equal(t, expectedHeader, recordsOne[0], "CSV header for posture_one is incorrect")
	require.Len(t, recordsOne, 3, "Expected header + 2 data rows for posture_one")

	// Expected sort order: custom/pol_A, sha/pol_B
	assert.Equal(t, "custom", recordsOne[1][0])
	assert.Equal(t, "pol_A", recordsOne[1][2])
	assert.Equal(t, "sha", recordsOne[2][0])
	assert.Equal(t, "pol_B", recordsOne[2][2])

	csvPathTwo := filepath.Join(mappingsDir, "posture_two_mappings.csv")
	_, err = os.Stat(csvPathTwo)
	require.NoError(t, err, "CSV file for posture_two should exist")

	fileTwo, err := os.Open(csvPathTwo)
	require.NoError(t, err)
	defer fileTwo.Close()

	readerTwo := csv.NewReader(fileTwo)
	recordsTwo, err := readerTwo.ReadAll()
	require.NoError(t, err)
	require.Equal(t, expectedHeader, recordsTwo[0], "CSV header for posture_two is incorrect")
	require.Len(t, recordsTwo, 3, "Expected header + 2 data rows for posture_two")

	// Expected sort order: custom/pol_A, orgpolicy/pol_C
	assert.Equal(t, "custom", recordsTwo[1][0])
	assert.Equal(t, "pol_A", recordsTwo[1][2])
	assert.Equal(t, "orgpolicy", recordsTwo[2][0])
	assert.Equal(t, "pol_C", recordsTwo[2][2])

	_, err = os.Stat(staleCsvPath)
	assert.True(t, os.IsNotExist(err), "Stale CSV file should have been deleted")
}

// TestGetFromMapSlice tests the getFromMapSlice function
func TestGetFromMapSlice(t *testing.T) {
	slice := yaml.MapSlice{
		{Key: "key1", Value: "value1"},
		{Key: "key2", Value: 123},
		{Key: "key3", Value: yaml.MapSlice{{Key: "nestedKey", Value: "nestedValue"}}},
	}

	t.Run("Existing key string", func(t *testing.T) {
		val := getFromMapSlice(slice, "key1")
		assert.Equal(t, "value1", val)
	})

	t.Run("Existing key int", func(t *testing.T) {
		val := getFromMapSlice(slice, "key2")
		assert.Equal(t, 123, val)
	})

	t.Run("Existing key nested map slice", func(t *testing.T) {
		val := getFromMapSlice(slice, "key3")
		expectedNested := yaml.MapSlice{{Key: "nestedKey", Value: "nestedValue"}}
		assert.Equal(t, expectedNested, val)
	})

	t.Run("Non-existent key", func(t *testing.T) {
		val := getFromMapSlice(slice, "nonExistentKey")
		assert.Nil(t, val)
	})

	t.Run("Empty map slice", func(t *testing.T) {
		emptySlice := yaml.MapSlice{}
		val := getFromMapSlice(emptySlice, "anyKey")
		assert.Nil(t, val)
	})
}

// TestLoadYAML tests the loadYAML function using afero
func TestLoadYAML(t *testing.T) {
	cleanup := setupTestEnvironment(t) // Mocks readFile
	defer cleanup()

	yamlFilePath := "test.yaml" // Use a path within the mock FS
	validYAMLContent := `
name: Test Item
details:
  version: 1.0
  active: true
list:
  - item1
  - item2
`
	createMockFile(t, MockFs, yamlFilePath, validYAMLContent)

	t.Run("Valid YAML file", func(t *testing.T) {
		ms, err := loadYAML(yamlFilePath) // Uses mocked readFile
		require.NoError(t, err)
		require.NotNil(t, ms)

		// Basic check for content
		assert.Equal(t, "name", (*ms)[0].Key)
		assert.Equal(t, "Test Item", (*ms)[0].Value)

		details, ok := (*ms)[1].Value.(yaml.MapSlice)
		assert.True(t, ok, "Expected 'details' to be a yaml.MapSlice")
		assert.Equal(t, "version", details[0].Key)
		assert.Equal(t, 1.0, details[0].Value) // YAML unmarshals numbers as float64 by default
	})

	t.Run("File not found", func(t *testing.T) {
		_, err := loadYAML("nonexistent.yaml") // Uses mocked readFile
		require.Error(t, err)
		// Check if the error is specifically a "file does not exist" error
		// afero might wrap the error, so checking the message is often reliable
		assert.Contains(t, err.Error(), "file does not exist", "Error should indicate file not found")
	})

	t.Run("Invalid YAML content", func(t *testing.T) {
		invalidYAMLPath := "invalid.yaml"
		createMockFile(t, MockFs, invalidYAMLPath, "name: Test\n  badIndent: true")
		_, err := loadYAML(invalidYAMLPath) // Uses mocked readFile
		require.Error(t, err)
		// We expect an error. For invalid YAML, it's often a parsing error from the yaml package.
		// Checking for "yaml:" in the error message is a reasonable heuristic.
		assert.Contains(t, err.Error(), "yaml:", "Error message should indicate a YAML parsing issue")
	})
}
