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
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2" // Import yaml package
)

// mockPolicyFile path for error messages in validation functions.
const mockPolicyFile = "testdata/mock_policy.yaml"

// Helper to unmarshal YAML string into a given struct
func unmarshalYAML(t *testing.T, yamlString string, target interface{}) {
	t.Helper()
	err := yaml.Unmarshal([]byte(yamlString), target)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML for test: %v", err)
	}
}

func TestValidateShaPolicy(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string // Test data as YAML string
		expectValid bool
	}{
		{
			name: "Valid SHA Module",
			yamlContent: `
moduleName: "SSL_NOT_ENFORCED"
moduleEnablementState: "ENABLED"
`,
			expectValid: true,
		},
		{
			name:        "Nil SHA Module (handled by validateDetectorPolicy)", // This case would be caught earlier
			yamlContent: `{}`,                                                 // Represents empty struct, but SHA module itself would be nil if not present under constraint
			expectValid: false,
		},
		{
			name: "Missing ModuleName",
			yamlContent: `
moduleName: ""
moduleEnablementState: "ENABLED"
`,
			expectValid: false,
		},
		{
			name: "Missing ModuleEnablementState",
			yamlContent: `
moduleName: "SSL_NOT_ENFORCED"
moduleEnablementState: ""
`,
			expectValid: false,
		},
		{
			name: "All fields missing (empty struct)",
			yamlContent: `
moduleName: ""
moduleEnablementState: ""
`,
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var shaModule SHAModule // Unmarshal into the actual struct from types.go
			unmarshalYAML(t, tt.yamlContent, &shaModule)

			// Special case for nil SHA Module: if the content is empty, it might result in a non-nil but empty struct
			// The validateShaPolicy itself explicitly checks for nil
			var ptrShaModule *SHAModule
			if tt.yamlContent != "{}" { // Assuming "{}" means "no module defined" for this specific test case
				ptrShaModule = &shaModule
			}

			isValid := validateShaPolicy(ptrShaModule, mockPolicyFile)
			assert.Equal(t, tt.expectValid, isValid, "Expected validation result mismatch")
		})
	}
}

func TestValidateCustomShaPolicy(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string // Test data as YAML string
		expectValid bool
	}{
		{
			name: "Valid Custom SHA Module",
			yamlContent: `
displayName: "Custom SHA Test"
config:
  predicate:
    expression: "resource.type == \"storage.googleapis.com/Bucket\""
  resourceSelector:
    resourceTypes:
      - "storage.googleapis.com/Bucket"
  severity: "HIGH"
  description: "Test custom SHA"
moduleEnablementState: "ENABLED"
`,
			expectValid: true,
		},
		{
			name:        "Nil Custom SHA Module (handled by validateDetectorPolicy)",
			yamlContent: `{}`,
			expectValid: false,
		},
		{
			name: "Missing DisplayName",
			yamlContent: `
displayName: ""
config:
  predicate:
    expression: "resource.type == \"storage.googleapis.com/Bucket\""
  resourceSelector:
    resourceTypes:
      - "storage.googleapis.com/Bucket"
  severity: "HIGH"
  description: "Test custom SHA"
moduleEnablementState: "ENABLED"
`,
			expectValid: false,
		},
		{
			name: "Missing ModuleEnablementState",
			yamlContent: `
displayName: "Custom SHA Test"
config:
  predicate:
    expression: "resource.type == \"storage.googleapis.com/Bucket\""
  resourceSelector:
    resourceTypes:
      - "storage.googleapis.com/Bucket"
  severity: "HIGH"
  description: "Test custom SHA"
moduleEnablementState: ""
`,
			expectValid: false,
		},
		{
			name: "Missing Config Predicate Expression (critical config field) - current func doesn't validate",
			yamlContent: `
displayName: "Custom SHA Test"
config:
  predicate:
    expression: "" # Missing expression
  resourceSelector:
    resourceTypes:
      - "storage.googleapis.com/Bucket"
  severity: "HIGH"
  description: "Test custom SHA"
moduleEnablementState: "ENABLED"
`,
			expectValid: true, // The current function doesn't validate internal config fields, only top-level
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var customSHAModule CustomSHAModule
			unmarshalYAML(t, tt.yamlContent, &customSHAModule)

			var ptrCustomSHAModule *CustomSHAModule
			if tt.yamlContent != "{}" {
				ptrCustomSHAModule = &customSHAModule
			}

			isValid := validateCustomShaPolicy(ptrCustomSHAModule, mockPolicyFile)
			assert.Equal(t, tt.expectValid, isValid, "Expected validation result mismatch")
		})
	}
}

func TestValidateOrgPolicy(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string // Test data as YAML string for OrgPolicyConstraint
		expectValid bool
	}{
		{
			name: "Valid Org Policy",
			yamlContent: `
cannedConstraintId: "constraints/compute.disableSerialPortAccess"
policyRules:
  - denyAll: true
  - listPolicy:
      allowedValues: ["projects/123"]
`,
			expectValid: true,
		},
		{
			name:        "Nil Org Policy Constraint (handled by validateDetectorPolicy)",
			yamlContent: `{}`,
			expectValid: false,
		},
		{
			name: "Missing CannedConstraintID",
			yamlContent: `
cannedConstraintId: ""
policyRules: []
`,
			expectValid: false,
		},
		{
			name: "Policy Rule with DenyAll and AllowAll both true",
			yamlContent: `
cannedConstraintId: "constraints/compute.disableSerialPortAccess"
policyRules:
  - denyAll: true
    allowAll: true
`,
			expectValid: false,
		},
		{
			name: "Policy Rule with AllowedValues and DeniedValues both present",
			yamlContent: `
cannedConstraintId: "constraints/compute.disableSerialPortAccess"
policyRules:
  - listPolicy:
      allowedValues: ["value1"]
      deniedValues: ["value2"]
`,
			expectValid: false,
		},
		{
			name: "Valid Org Policy with empty PolicyRules",
			yamlContent: `
cannedConstraintId: "constraints/compute.disableSerialPortAccess"
policyRules: []
`,
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var orgPolicyConstraint OrgPolicyConstraint
			unmarshalYAML(t, tt.yamlContent, &orgPolicyConstraint)

			var ptrOrgPolicyConstraint *OrgPolicyConstraint
			if tt.yamlContent != "{}" {
				ptrOrgPolicyConstraint = &orgPolicyConstraint
			}

			isValid := validateOrgPolicy(ptrOrgPolicyConstraint, mockPolicyFile)
			assert.Equal(t, tt.expectValid, isValid, "Expected validation result mismatch")
		})
	}
}

func TestValidateCustomOrgPolicy(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string // Test data as YAML string for CustomOrgPolicyConstraint
		expectValid bool
	}{
		{
			name: "Valid Custom Org Policy",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE", "UPDATE"]
  resourceTypes:
    - "cloudresourcemanager.googleapis.com/Project"
policyRules:
  - enforce: true
  - enforce: true
    condition:
      description: "Rule condition"
      expression: "resource.labels.env == 'prod'"
      title: "Prod Environment"
`,
			expectValid: true,
		},
		{
			name:        "Nil Custom Org Policy Constraint (handled by validateDetectorPolicy)",
			yamlContent: `{}`,
			expectValid: false,
		},
		{
			name: "Missing CustomConstraint Name",
			yamlContent: `
customConstraint:
  name: ""
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
`,
			expectValid: false,
		},
		{
			name: "Missing CustomConstraint DisplayName",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: ""
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
`,
			expectValid: false,
		},
		{
			name: "Missing CustomConstraint Description",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: ""
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
`,
			expectValid: false,
		},
		{
			name: "Missing CustomConstraint ActionType",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: ""
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
`,
			expectValid: false,
		},
		{
			name: "Missing CustomConstraint Condition",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: ""
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
`,
			expectValid: false,
		},
		{
			name: "Empty CustomConstraint MethodTypes",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: []
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
`,
			expectValid: false,
		},
		{
			name: "Empty CustomConstraint ResourceTypes",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: []
`,
			expectValid: false,
		},
		{
			name: "Missing Rule Condition Description",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
policyRules:
  - enforce: true
    condition:
      description: "" # Missing
      expression: "resource.labels.env == 'prod'"
      title: "Prod Environment"
`,
			expectValid: false,
		},
		{
			name: "Missing Rule Condition Expression",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
policyRules:
  - enforce: true
    condition:
      description: "Rule condition"
      expression: "" # Missing
      title: "Prod Environment"
`,
			expectValid: false,
		},
		{
			name: "Missing Rule Condition Title",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
policyRules:
  - enforce: true
    condition:
      description: "Rule condition"
      expression: "resource.labels.env == 'prod'"
      title: "" # Missing
`,
			expectValid: false,
		},
		{
			name: "Valid Custom Org Policy with empty PolicyRules",
			yamlContent: `
customConstraint:
  name: "test.custom.policy"
  displayName: "Test Custom Org Policy"
  description: "This is a test custom org policy."
  actionType: "ALLOW"
  condition: "resource.name.contains(\"test\")"
  methodTypes: ["CREATE"]
  resourceTypes: ["cloudresourcemanager.googleapis.com/Project"]
policyRules: []
`,
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var customOrgPolicyConstraint CustomOrgPolicyConstraint
			unmarshalYAML(t, tt.yamlContent, &customOrgPolicyConstraint)

			var ptrCustomOrgPolicyConstraint *CustomOrgPolicyConstraint
			if tt.yamlContent != "{}" {
				// CORRECTED LINE: Removed the extra "Policy" from the variable name
				ptrCustomOrgPolicyConstraint = &customOrgPolicyConstraint
			}

			isValid := validateCustomOrgPolicy(ptrCustomOrgPolicyConstraint, mockPolicyFile)
			assert.Equal(t, tt.expectValid, isValid, "Expected validation result mismatch")
		})
	}
}
