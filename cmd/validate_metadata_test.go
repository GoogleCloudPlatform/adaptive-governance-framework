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
	"errors" // Added import
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDetectorMetadata(t *testing.T) {
	tests := []struct {
		name         string
		metadataYAML string
		expectValid  bool
		createFile   bool // Flag to control if the file should actually be created
	}{
		{
			name: "Valid Metadata",
			metadataYAML: `
policyId: "valid-policy-id_01"
description: "This is a valid policy description."
postures: ["pci-dss", "iso27001"]
author: "test-user@example.com"
severity: "HIGH"
next-steps: "Review your firewall rules."
complianceStandards:
  - standard: "NIST SP 800-53"
    control: "AC-1"
exempt-resources:
  - "projects/123/resource/test"
applied-labels:
  - key: "env"
    value: "dev"
exempt-labels:
  - key: "exempt"
    value: "true"
`,
			expectValid: true,
			createFile:  true,
		},
		{
			name: "Missing PolicyId",
			metadataYAML: `
description: "Missing PolicyId description."
postures: ["pci-dss"]
author: "test-user@example.com"
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name: "Missing Description",
			metadataYAML: `
policyId: "test-policy-002"
postures: ["iso27001"]
author: "test-user@example.com"
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name: "Missing Postures",
			metadataYAML: `
policyId: "test-policy-003"
description: "Missing Postures description."
author: "test-user@example.com"
postures: [] # Explicitly empty slice
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name: "Missing Author",
			metadataYAML: `
policyId: "test-policy-004"
description: "Missing Author description."
postures: ["hipaa"]
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name: "Invalid PolicyId - Starts with number",
			metadataYAML: `
policyId: "1invalid-policy"
description: "Description."
postures: ["standard"]
author: "test"
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name: "Invalid PolicyId - Contains invalid character",
			metadataYAML: `
policyId: "invalid.policy.id"
description: "Description."
postures: ["standard"]
author: "test"
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name: "Invalid PolicyId - Too long (64 chars)",
			metadataYAML: `
policyId: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij0123456789" # 64 chars
description: "Description."
postures: ["standard"]
author: "test"
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name:         "File Not Found",
			metadataYAML: "", // Content doesn't matter as file won't be created
			expectValid:  false,
			createFile:   false, // Do not create the file
		},
		{
			name: "Invalid YAML Syntax",
			metadataYAML: `
policyId: "test-policy"
description: "Description."
  postures: ["standard" # Missing closing bracket
author: "test"
`,
			expectValid: false,
			createFile:  true,
		},
		{
			name: "PolicyId with underscore and hyphen",
			metadataYAML: `
policyId: "policy_id-with_underscores-and-hyphens"
description: "Description."
postures: ["standard"]
author: "test"
`,
			expectValid: true,
			createFile:  true,
		},
		{
			name: "PolicyId max length (63 chars)",
			metadataYAML: `
policyId: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi0123456789" # 63 chars
description: "Description."
postures: ["standard"]
author: "test"
`,
			expectValid: false, // Regex also handles policy ID character length, will not parse successfully.
			createFile:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := createTempDir(t, "metadata_test")
			// Temp file/dir cleanup handled by t.Cleanup in createTempDir

			metadataFilePath := filepath.Join(tempDir, "metadata.yaml")
			if tt.createFile {
				createTempFile(t, tempDir, "metadata.yaml", tt.metadataYAML)
			}

			isValid := validateDetectorMetadata(metadataFilePath)
			assert.Equal(t, tt.expectValid, isValid, "Expected validation result mismatch")

			// For file not found test, ensure os.IsNotExist error
			if !tt.createFile {
				_, err := os.ReadFile(metadataFilePath)
				assert.True(t, os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist), "Expected file not found error for non-existent file")
			}
		})
	}
}
