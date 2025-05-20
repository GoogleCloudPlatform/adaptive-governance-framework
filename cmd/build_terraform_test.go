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
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v2"
)

func TestNormalizePolicyID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no spaces", "policy123", "policy123"},
		{"leading/trailing spaces", "  policy 123  ", "policy_123"},
		{"internal spaces", "my policy name", "my_policy_name"},
		{"multiple internal spaces", "my  policy  name", "my__policy__name"},
		{"empty string", "", ""},
		{"only spaces", "   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizePolicyID(tt.input))
		})
	}
}

// BuildTerraform_TestExtractMetadata tests metadata extraction for the purpose of building postures
func BuildTerraform_TestExtractMetadata(t *testing.T) {
	// This function variable should be declared in main.go and initialized to os.ReadFile
	// For testing, setupMockFs will override it.
	originalReadFile := osReadFile
	defer func() { osReadFile = originalReadFile }() // Restore original function after test
	setupMockFs()

	validMetadataContent := `
policyId: "test-policy-001"
description: "A test policy description."
postures:
  - "posture_A"
  - "posture_B"
complianceStandards:
  - standard: "NIST"
    control: "CM-7"
`
	createMockFile(t, MockFs, "metadata_valid.yaml", validMetadataContent)

	missingFieldsMetadataContent := `
policyId: "test-policy-002"
# description: "Missing description"
postures:
  - "posture_C"
complianceStandards:
  - standard: "CIS"
    control: "1.1"
`
	createMockFile(t, MockFs, "metadata_missing.yaml", missingFieldsMetadataContent)
	createMockFile(t, MockFs, "metadata_invalid_yaml.yaml", "policyId: test\ndescription: test\npostures: [test]\ncomplianceStandards: [{standard: s, control: c}]\n  bad_indent: true")

	tests := []struct {
		name        string
		filePath    string
		expectError bool
		expectedID  string
		errorMsg    string
	}{
		{
			name:        "valid metadata",
			filePath:    "metadata_valid.yaml",
			expectError: false,
			expectedID:  "test-policy-001",
		},
		{
			name:        "file not found",
			filePath:    "metadata_notfound.yaml",
			expectError: true,
			errorMsg:    "failed to read metadata file",
		},
		{
			name:        "invalid yaml",
			filePath:    "metadata_invalid_yaml.yaml",
			expectError: true,
			errorMsg:    "failed to parse metadata file",
		},
		{
			name:        "missing required fields",
			filePath:    "metadata_missing.yaml",
			expectError: true,
			errorMsg:    "invalid metadata in metadata_missing.yaml: missing required keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata, err := extractMetadata(tt.filePath)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, metadata)
				assert.Equal(t, tt.expectedID, metadata.PolicyID)
				assert.Equal(t, "A test policy description.", metadata.Description)
				assert.Len(t, metadata.Postures, 2)
				assert.Len(t, metadata.ComplianceStandards, 1)
			}
		})
	}
}

func TestGetTerraformFiles(t *testing.T) {
	originalReadDir := osReadDir
	defer func() { osReadDir = originalReadDir }()
	setupMockFs()

	tfDir := "test_tf_dir"
	require.NoError(t, MockFs.MkdirAll(tfDir, 0755))
	createMockFile(t, MockFs, filepath.Join(tfDir, "main.tf"), "# main terraform file")
	createMockFile(t, MockFs, filepath.Join(tfDir, "variables.tf"), "# variables")
	createMockFile(t, MockFs, filepath.Join(tfDir, "outputs.tf"), "# outputs")
	createMockFile(t, MockFs, filepath.Join(tfDir, "other.txt"), "not a terraform file")
	require.NoError(t, MockFs.MkdirAll(filepath.Join(tfDir, "modules"), 0755)) // a subdirectory

	t.Run("valid terraform files", func(t *testing.T) {
		// Ensure getTerraformFiles uses the mocked osReadDir
		files := getTerraformFiles(tfDir)
		assert.ElementsMatch(t, []string{"main.tf", "variables.tf", "outputs.tf"}, files)
	})

	emptyDir := "empty_tf_dir"
	require.NoError(t, MockFs.MkdirAll(emptyDir, 0755))
	t.Run("empty directory", func(t *testing.T) {
		files := getTerraformFiles(emptyDir)
		assert.Empty(t, files)
	})

	noTfDir := "no_tf_files_dir"
	require.NoError(t, MockFs.MkdirAll(noTfDir, 0755))
	createMockFile(t, MockFs, filepath.Join(noTfDir, "script.sh"), "# a script")
	t.Run("directory with no tf files", func(t *testing.T) {
		files := getTerraformFiles(noTfDir)
		assert.Empty(t, files)
	})
}

func TestSortPolicyTypes(t *testing.T) {
	policies := map[string]map[string]*Policy{
		"orgpolicy":       nil,
		"sha":             nil,
		"customsha":       nil,
		"customorgpolicy": nil,
	}
	expected := []string{"customorgpolicy", "customsha", "orgpolicy", "sha"}
	sorted := sortPolicyTypes(policies)
	assert.Equal(t, expected, sorted)
}

func TestSortPolicies(t *testing.T) {
	policiesMap := map[string]*Policy{
		"policy-c": {PolicyID: "policy-c"},
		"policy-a": {PolicyID: "policy-a"},
		"policy-b": {PolicyID: "policy-b"},
	}
	expected := []*Policy{
		{PolicyID: "policy-a"},
		{PolicyID: "policy-b"},
		{PolicyID: "policy-c"},
	}
	sorted := sortPolicies(policiesMap)
	assert.Equal(t, expected, sorted)
}

func TestCreateStringVals(t *testing.T) {
	input := []string{"a", "b", "c"}
	expected := []cty.Value{cty.StringVal("a"), cty.StringVal("b"), cty.StringVal("c")}
	assert.Equal(t, expected, createStringVals(input))

	inputEmpty := []string{}
	expectedEmpty := []cty.Value{}
	assert.Equal(t, expectedEmpty, createStringVals(inputEmpty))
}

func TestUpdateTerraform_BasicScenarios(t *testing.T) {
	originalReadFile, originalWriteFile, originalReadDir := osReadFile, osWriteFile, osReadDir
	defer func() { osReadFile, osWriteFile, osReadDir = originalReadFile, originalWriteFile, originalReadDir }()
	setupMockFs()

	terraformDir := "postures_dir"
	postureFileName := "posture_alpha.tf"
	createMockFile(t, MockFs, filepath.Join(terraformDir, postureFileName), `
resource "google_securityposture_posture" "default" {
  posture_id = "my_posture"
  parent     = "organizations/12345"
  location   = "global"
  description = "Base posture"

  policy_sets {
    policy_set_id = "sha_policy_set"
    description   = "::DO NOT EDIT::Policy Set for only sha policies, auto-inlined from repository."

    policies {
      policy_id = "old-sha-policy"
      description = "This one should be removed"
      constraint {
        security_health_analytics_module {
          module_name = "OLD_MODULE"
          module_enablement_state = "ENABLED"
        }
      }
    }
  }

  policy_sets {
    policy_set_id = "orgpolicy_policy_set"
    description   = "::DO NOT EDIT::Policy Set for only orgpolicy policies, auto-inlined from repository."
    // This policy set will be empty and then populated
  }

  policy_sets {
    policy_set_id = "legacy_policy_set_to_remove" // This should be removed
    description   = "This policy set is not in the allowed list"
	policies {
      policy_id = "legacy-policy"
      description = "Legacy"
      constraint { # dummy constraint
        org_policy_constraint {
          canned_constraint_id = "constraints/compute.disableSerialPortAccess"
        }
      }
    }
  }
}
`)
	createMockFile(t, MockFs, filepath.Join(terraformDir, "posture_beta.tf"), `
resource "google_securityposture_posture" "beta" {
  posture_id = "beta_posture"
  parent     = "organizations/12345"
  location   = "global"
}
`) // posture_beta.tf for testing posture filtering

	policies := map[string]map[string]*Policy{
		"sha": {
			"new-sha-1": &Policy{PolicyID: "new-sha-1", Constraint: &Constraint{SHAModule: &SHAModule{"NEW_SHA_MODULE", "ENABLED"}}},
		},
		"orgpolicy": {
			"new-org-1": &Policy{PolicyID: "new-org-1", Constraint: &Constraint{OrgPolicyConstraint: &OrgPolicyConstraint{
				CannedConstraintID: "constraints/compute.requireShieldedVm",
				PolicyRules: []struct {
					DenyAll    bool `yaml:"denyAll"`
					AllowAll   bool `yaml:"allowAll"`
					ListPolicy *struct {
						AllowedValues     []string `yaml:"allowedValues"`
						DeniedValues      []string `yaml:"deniedValues"`
						InheritFromParent bool     `yaml:"inheritFromParent"`
						SuggestedValue    string   `yaml:"suggestedValue"`
					} `yaml:"listPolicy,omitempty"`
					Condition *struct {
						Description string `yaml:"description"`
						Expression  string `yaml:"expression"`
						Title       string `yaml:"title"`
					} `yaml:"condition,omitempty"`
					Parameters *struct {
						Fields []struct {
							Key   string `yaml:"key"`
							Value *struct {
								BoolValue   bool   `yaml:"bool_value,omitempty"`
								NullValue   string `yaml:"null_value,omitempty"`
								StringValue string `yaml:"string_value,omitempty"`
							} `yaml:"value,omitempty"`
						} `yaml:"fields,omitempty"`
					} `yaml:"parameters,omitempty"`
					ResourceTypes *struct {
						Included string `yaml:"included"`
					} `yaml:"resource_types,omitempty"`
				}{{AllowAll: true}},
			}}},
			"org-for-beta-only": &Policy{PolicyID: "org-for-beta-only", Constraint: &Constraint{OrgPolicyConstraint: &OrgPolicyConstraint{
				CannedConstraintID: "constraints/iam.disableServiceAccountKeyCreation",
				PolicyRules: []struct {
					DenyAll    bool `yaml:"denyAll"`
					AllowAll   bool `yaml:"allowAll"`
					ListPolicy *struct {
						AllowedValues     []string `yaml:"allowedValues"`
						DeniedValues      []string `yaml:"deniedValues"`
						InheritFromParent bool     `yaml:"inheritFromParent"`
						SuggestedValue    string   `yaml:"suggestedValue"`
					} `yaml:"listPolicy,omitempty"`
					Condition *struct {
						Description string `yaml:"description"`
						Expression  string `yaml:"expression"`
						Title       string `yaml:"title"`
					} `yaml:"condition,omitempty"`
					Parameters *struct {
						Fields []struct {
							Key   string `yaml:"key"`
							Value *struct {
								BoolValue   bool   `yaml:"bool_value,omitempty"`
								NullValue   string `yaml:"null_value,omitempty"`
								StringValue string `yaml:"string_value,omitempty"`
							} `yaml:"value,omitempty"`
						} `yaml:"fields,omitempty"`
					} `yaml:"parameters,omitempty"`
					ResourceTypes *struct {
						Included string `yaml:"included"`
					} `yaml:"resource_types,omitempty"`
				}{{AllowAll: true}},
			}}},
		},
		"customsha": { // New policy set to be created
			"new-customsha-1": &Policy{PolicyID: "new-customsha-1", Constraint: &Constraint{CustomSHAModule: &CustomSHAModule{
				DisplayName: "My New Custom SHA",
				Config: struct {
					Predicate struct {
						Expression string `yaml:"expression"`
					} `yaml:"predicate"`
					CustomOutput *struct {
						Properties []struct {
							Name            string `yaml:"name"`
							ValueExpression struct {
								Expression string `yaml:"expression"`
							} `yaml:"valueExpression"`
						} `yaml:"properties"`
					} `yaml:"customOutput,omitempty"`
					ResourceSelector *struct {
						ResourceTypes []string `yaml:"resourceTypes"`
					} `yaml:"resourceSelector"`
					Severity       string `yaml:"severity"`
					Description    string `yaml:"description"`
					Recommendation string `yaml:"recommendation,omitempty"`
				}{
					Predicate: struct {
						Expression string `yaml:"expression"`
					}{"true"},
					ResourceSelector: &struct {
						ResourceTypes []string `yaml:"resourceTypes"`
					}{[]string{"*"}}, // ResourceSelector is present
					Severity: "LOW", Description: "A new custom sha",
					// CustomOutput is nil for this policy
				},
				ModuleEnablementState: "ENABLED",
			}}},
		},
	}

	allMetadata := map[string]*Metadata{
		"new-sha-1":         {PolicyID: "new-sha-1", Description: "New SHA Policy", Postures: []string{"posture_alpha"}, PolicyFileName: "detectors/sha/new-sha-1/metadata.yaml"},
		"new-org-1":         {PolicyID: "new-org-1", Description: "New Org Policy", Postures: []string{"posture_alpha"}, PolicyFileName: "detectors/orgpolicy/new-org-1/metadata.yaml"},
		"org-for-beta-only": {PolicyID: "org-for-beta-only", Description: "Org for Beta", Postures: []string{"posture_beta"}, PolicyFileName: "detectors/orgpolicy/org-for-beta-only/metadata.yaml"},
		"new-customsha-1":   {PolicyID: "new-customsha-1", Description: "New Custom SHA", Postures: []string{"posture_alpha"}, PolicyFileName: "detectors/customsha/new-customsha-1/metadata.yaml"},
	}

	err := updateTerraform(terraformDir, policies, allMetadata)
	require.NoError(t, err) // Check if updateTerraform itself returns an error

	// --- Assertions for posture_alpha.tf ---
	updatedContentAlphaBytes, err := afero.ReadFile(MockFs, filepath.Join(terraformDir, postureFileName))
	require.NoError(t, err)
	updatedContentAlpha := string(updatedContentAlphaBytes)

	// Check SHA policy set - Use exact string from error output if possible
	assert.Contains(t, updatedContentAlpha, `policy_set_id = "sha_policy_set"`)
	assert.Contains(t, updatedContentAlpha, `policy_id = "new-sha-1"`)
	// Use a specific substring that includes quotes and spacing as seen in HCL output
	assert.Contains(t, updatedContentAlpha, `module_name             = "NEW_SHA_MODULE"`, "SHA module_name mismatch")
	assert.NotContains(t, updatedContentAlpha, "old-sha-policy") // Old policy removed

	// Check Orgpolicy policy set
	assert.Contains(t, updatedContentAlpha, `policy_set_id = "orgpolicy_policy_set"`)
	assert.Contains(t, updatedContentAlpha, `policy_id = "new-org-1"`)
	assert.Contains(t, updatedContentAlpha, `canned_constraint_id = "constraints/compute.requireShieldedVm"`)
	assert.NotContains(t, updatedContentAlpha, "org-for-beta-only") // Should not be in alpha

	// Check CustomSHA policy set (newly created)
	assert.Contains(t, updatedContentAlpha, `policy_set_id = "customsha_policy_set"`)
	assert.Contains(t, updatedContentAlpha, `policy_id = "new-customsha-1"`)
	// Use a specific substring that includes quotes and spacing as seen in HCL output
	assert.Contains(t, updatedContentAlpha, `display_name            = "My New Custom SHA"`, "CustomSHA display_name mismatch")

	// Check legacy policy set removed
	assert.NotContains(t, updatedContentAlpha, "legacy_policy_set_to_remove")
	assert.NotContains(t, updatedContentAlpha, "legacy-policy")

	// --- Assertions for posture_beta.tf ---
	updatedContentBetaBytes, err := afero.ReadFile(MockFs, filepath.Join(terraformDir, "posture_beta.tf"))
	require.NoError(t, err)
	updatedContentBeta := string(updatedContentBetaBytes)

	assert.Contains(t, updatedContentBeta, `policy_set_id = "orgpolicy_policy_set"`)
	assert.Contains(t, updatedContentBeta, `policy_id = "org-for-beta-only"`)
	assert.Contains(t, updatedContentBeta, `canned_constraint_id = "constraints/iam.disableServiceAccountKeyCreation"`)
	assert.NotContains(t, updatedContentBeta, `policy_id = "new-org-1"`)          // Should not be in beta
	assert.NotContains(t, updatedContentBeta, `policy_set_id = "sha_policy_set"`) // No SHA policies for beta
}

func TestUpdateTerraform_NoPostureResource(t *testing.T) {
	originalReadFile, originalWriteFile, originalReadDir := osReadFile, osWriteFile, osReadDir
	defer func() { osReadFile, osWriteFile, osReadDir = originalReadFile, originalWriteFile, originalReadDir }()
	setupMockFs()
	createMockFile(t, MockFs, "test.tf", `resource "other" "x" {}`)
	err := updateTerraform(".", make(map[string]map[string]*Policy), make(map[string]*Metadata))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no 'google_securityposture_posture' resource found") // Verify specific error message
}

func TestUpdateTerraform_MetadataNotFound(t *testing.T) {
	originalReadFile, originalWriteFile, originalReadDir := osReadFile, osWriteFile, osReadDir
	defer func() { osReadFile, osWriteFile, osReadDir = originalReadFile, originalWriteFile, originalReadDir }()
	setupMockFs()
	createMockFile(t, MockFs, "test.tf", `resource "google_securityposture_posture" "default" {}`)
	// Initialize PolicyID within Policy struct
	policies := map[string]map[string]*Policy{"sha": {"p1": {PolicyID: "p1"}}} // Set PolicyID here
	err := updateTerraform(".", policies, make(map[string]*Metadata))          // allMetadata is empty
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata not found for policy ID: p1") // Verify specific error message
}

func TestMainFunction_Simplified(t *testing.T) {
	originalReadFile, originalWriteFile, originalReadDir, originalFilepathWalk := osReadFile, osWriteFile, osReadDir, filepathWalk
	defer func() {
		osReadFile, osWriteFile, osReadDir, filepathWalk = originalReadFile, originalWriteFile, originalReadDir, originalFilepathWalk
	}()
	setupMockFs()

	detectorsDirRoot := "mock_detectors_main"
	tfDirRoot := "mock_build_main/postures"

	shaPolicyDir := filepath.Join(detectorsDirRoot, "sha", "main-sha-policy")

	shaMetadataContent := `
policyId: "sha_ABC"
description: "Test SHA policy from main"
postures: 
  - "target_posture"
complianceStandards: 
  - standard: "PCI"
    control: "1.0"
`
	shaPolicyContent := `
policy_id: "x" # This ID from the file is normalized then replaced by metadata.PolicyID
constraint:
  securityHealthAnalyticsModule:
    moduleName: "MY_MAIN_SHA_MODULE"
    moduleEnablementState: "ENABLED"
`
	createMockFile(t, MockFs, filepath.Join(shaPolicyDir, "metadata.yaml"), shaMetadataContent)
	createMockFile(t, MockFs, filepath.Join(shaPolicyDir, "policy.yaml"), shaPolicyContent)
	orgPolicyDir := filepath.Join(detectorsDirRoot, "orgpolicy", "my-org-policy")
	orgMetadataContent := `
policyId: "org_XYZ"
description: "Test ORG policy from main"
postures: 
  - "target_posture"
complianceStandards: 
  - standard: "HIPAA"
    control: "2.0"
`
	orgPolicyContent := `
policy_id: "y" # This ID from the file is normalized then replaced by metadata.PolicyID
constraint: 
  orgPolicyConstraint: 
    cannedConstraintId: "constraints/iam.allowedPolicyMemberDomains"
    policyRules: 
      - listPolicy: 
          allowedValues: ["example.com"]
`
	createMockFile(t, MockFs, filepath.Join(orgPolicyDir, "metadata.yaml"), orgMetadataContent)
	createMockFile(t, MockFs, filepath.Join(orgPolicyDir, "policy.yaml"), orgPolicyContent)

	targetTF := filepath.Join(tfDirRoot, "target_posture.tf")
	mockTFContent := `
resource "google_securityposture_posture" "main_test" {
  posture_id = "target_posture_id"
  parent = "organizations/999"
  location = "global"
  policy_sets = {}
}`
	createMockFile(t, MockFs, targetTF, mockTFContent)

	filepathWalk = func(root string, walkFn filepath.WalkFunc) error {
		if root != "detectors" {
			if root == "detectors" && strings.HasPrefix(detectorsDirRoot, "mock_") {
				return afero.Walk(MockFs, detectorsDirRoot, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					relPath, _ := filepath.Rel(detectorsDirRoot, path)
					mainViewPath := filepath.Join("detectors", relPath)
					return walkFn(mainViewPath, info, err)
				})
			}
			return fmt.Errorf("filepathWalk mock called with unexpected root: %s", root)
		}
		return afero.Walk(MockFs, detectorsDirRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			adjustedPath := strings.Replace(path, detectorsDirRoot, "detectors", 1)
			return walkFn(adjustedPath, info, err)
		})
	}

	policies := make(map[string]map[string]*Policy)
	allMetadata := make(map[string]*Metadata)

	err := filepathWalk("detectors", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "policy.yaml" {
			mockPath := strings.Replace(path, "detectors", detectorsDirRoot, 1)
			metadataFile := filepath.Join(filepath.Dir(mockPath), "metadata.yaml")
			policyType := strings.Split(filepath.Dir(path), string(os.PathSeparator))[1]

			metadata, errMet := extractMetadata(metadataFile)
			if errMet != nil {
				return fmt.Errorf("test main: failed to extract metadata from %s (orig path %s): %w", metadataFile, path, errMet)
			}

			policyData, errRead := osReadFile(mockPath)
			if errRead != nil {
				return fmt.Errorf("test main: failed to read policy file %s: %w", mockPath, errRead)
			}
			var policy Policy
			errYaml := yaml.Unmarshal(policyData, &policy)
			if errYaml != nil {
				return fmt.Errorf("test main: failed to parse policy file %s: %w", mockPath, errYaml)
			}
			policy.PolicyID = normalizePolicyID(policy.PolicyID)
			policy.PolicyID = metadata.PolicyID
			metadata.PolicyFileName = filepath.Dir(mockPath)
			policy.MetadataName = metadata.PolicyID

			if _, ok := policies[policyType]; !ok {
				policies[policyType] = make(map[string]*Policy)
			}
			policies[policyType][metadata.PolicyID] = &policy
			allMetadata[metadata.PolicyID] = metadata
		}
		return nil
	})
	require.NoError(t, err, "Simulated filepath.Walk in TestMainFunction_Simplified failed")

	err = updateTerraform(tfDirRoot, policies, allMetadata)
	require.NoError(t, err, "updateTerraform call in TestMainFunction_Simplified failed")

	updatedBytes, _ := afero.ReadFile(MockFs, targetTF)
	updatedContent := string(updatedBytes)

	// Check SHA policy set
	assert.Contains(t, updatedContent, `policy_set_id = "sha_policy_set"`)
	assert.Contains(t, updatedContent, `policy_id = "sha_ABC"`)
	// Use a specific substring that includes quotes and spacing as seen in HCL output
	assert.Contains(t, updatedContent, `module_name             = "MY_MAIN_SHA_MODULE"`, "SHA module_name mismatch")
	assert.Contains(t, updatedContent, `standard = "PCI"`)

	// Check Orgpolicy policy set
	assert.Contains(t, updatedContent, `policy_set_id = "orgpolicy_policy_set"`)
	assert.Contains(t, updatedContent, `policy_id = "org_XYZ"`)
	assert.Contains(t, updatedContent, `canned_constraint_id = "constraints/iam.allowedPolicyMemberDomains"`)
	assert.Contains(t, updatedContent, `standard = "HIPAA"`)
}
