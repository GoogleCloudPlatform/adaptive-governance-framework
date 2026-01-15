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
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDir remains the same
func setupTestDir(t *testing.T) (string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "posture_test_*")
	require.NoError(t, err, "Failed to create temp directory")
	originalWD, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")
	err = os.Chdir(tempDir)
	require.NoError(t, err, "Failed to change to temp directory")
	return tempDir, func() {
		_ = os.Chdir(originalWD)
		_ = os.RemoveAll(tempDir)
	}
}

// TestNewPosture_Success remains the same
func TestNewPosture_Success(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()
	name := "test_success_posture"
	description := "A successful test posture."
	parentOrg := "organizations/12345" // Valid format
	targetRes := "folders/67890"       // Valid format

	var outBuf bytes.Buffer
	err := NewPosture(&outBuf, name, description, parentOrg, targetRes)
	require.NoError(t, err, "NewPosture failed with valid inputs")
	output := outBuf.String()
	tfFilePathInTempDir := filepath.Join("build", "postures", name+".tf")
	_, statErr := os.Stat(tfFilePathInTempDir)
	assert.NoError(t, statErr, "Terraform file should be created at: %s", tfFilePathInTempDir)
	content, readErr := os.ReadFile(tfFilePathInTempDir)
	require.NoError(t, readErr, "Failed to read Terraform file: %s", tfFilePathInTempDir)
	contentStr := string(content)
	assert.Contains(t, contentStr, `resource "google_securityposture_posture" "test_success_posture"`)
	assert.Contains(t, contentStr, `parent      = "organizations/12345"`)
	assert.Contains(t, contentStr, `description = "A successful test posture."`)
	assert.Contains(t, contentStr, `target_resource       = "folders/67890"`)
	assert.Contains(t, output, "Successfully created posture files:")
	expectedOutputPath := filepath.Join("build", "postures", name+".tf")
	assert.Contains(t, output, expectedOutputPath)
}

// TestNewPosture_InputValidation remains the same
func TestNewPosture_InputValidation(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()
	testCases := []struct {
		name        string
		pName       string
		pDesc       string
		pParent     string
		pTarget     string
		expectedErr string
	}{
		{"InvalidNameChars", "invalid-name!", "desc", "organizations/123", "folders/456", "name 'invalid-name!' is invalid"},
		{"InvalidParentFormat", "valid_name", "desc", "org/123", "folders/456", "parent 'org/123' is invalid"},
		{"InvalidTargetFormat", "valid_name", "desc", "organizations/123", "project/abc", "target 'project/abc' is invalid"},
		{"EmptyNameInvalidFormat", "", "desc", "organizations/123", "folders/456", "name '' is invalid"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewPosture(io.Discard, tc.pName, tc.pDesc, tc.pParent, tc.pTarget)
			require.Error(t, err, "Expected an error for test case: %s", tc.name)
			assert.Contains(t, err.Error(), tc.expectedErr, "Error message mismatch for test case: %s", tc.name)
		})
	}
}

// TestGenerateRandomLetterID remains the same
func TestGenerateRandomLetterID(t *testing.T) {
	t.Run("ValidLength", func(t *testing.T) {
		length := 10
		id, err := generateRandomLetterID(length)
		require.NoError(t, err)
		assert.Len(t, id, length)
		for _, char := range id {
			isLetter := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
			assert.True(t, isLetter)
		}
	})
	t.Run("ZeroLength", func(t *testing.T) {
		_, err := generateRandomLetterID(0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "positive integer")
	})
	t.Run("NegativeLength", func(t *testing.T) {
		_, err := generateRandomLetterID(-5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "positive integer")
	})
}

// Helper function to create a new, clean instance of newPostureCmd for testing.
func createTestNewPostureCmd() *cobra.Command {
	// Create a new command instance for each test run to ensure flag isolation.
	cmdInstance := &cobra.Command{
		Use:   "new-posture", // Must match the name used in SetArgs
		Short: "Test: Creates the necessary files for a new security posture.",
		Long:  `Test: A longer description.`,
		RunE: func(c *cobra.Command, args []string) error {
			// Fetch flags directly from this command instance (c)
			nameVal, _ := c.Flags().GetString("name") // Error ignored as presence is for MarkFlagRequired
			descVal, _ := c.Flags().GetString("description")
			parentVal, _ := c.Flags().GetString("parent")
			targetVal, _ := c.Flags().GetString("target")
			return NewPosture(c.OutOrStdout(), nameVal, descVal, parentVal, targetVal)
		},
		// DisableFlagParsing: true, // This can sometimes help if Cobra's parsing is too aggressive before Execute
	}

	// Define flags directly on this fresh instance.
	// Do NOT bind to package-level global variables (Name, Description, etc.) here
	// to ensure test isolation from the global newPostureCmd instance.
	cmdInstance.Flags().StringP("name", "n", "", "The name for the Terraform posture file (alphanumeric + underscore, e.g., 'folder_b_posture') (required)")
	cmdInstance.Flags().StringP("description", "d", "", "The description for the posture resource (required)")
	cmdInstance.Flags().StringP("parent", "p", "", "The organization/folder/project node where the posture resource itself will be created. E.g., organizations/123. (required)")
	cmdInstance.Flags().StringP("target", "t", "", "The hierarchy node this posture will target for deployment. E.g., organizations/123, folders/123, projects/123. (required)")

	// Mark flags as required on this specific instance.
	// The error from MarkFlagRequired is ignored here as it would only fail if the flag wasn't defined above.
	_ = cmdInstance.MarkFlagRequired("name")
	_ = cmdInstance.MarkFlagRequired("description")
	_ = cmdInstance.MarkFlagRequired("parent")
	_ = cmdInstance.MarkFlagRequired("target")

	return cmdInstance
}

// Test_NewPostureCmd tests the cobra command execution using fresh command instances.
func Test_NewPostureCmd(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		_, cleanup := setupTestDir(t)
		defer cleanup()

		testCmd := createTestNewPostureCmd()
		// Use a temporary root command for testing this specific subcommand.
		rootTestCmd := &cobra.Command{Use: "agf-test-root"}
		rootTestCmd.AddCommand(testCmd)

		buf := new(bytes.Buffer)
		rootTestCmd.SetOut(buf)
		rootTestCmd.SetErr(buf)

		args := []string{
			"new-posture", // Command to execute (must match testCmd.Use)
			"--name", "cmd_test_posture",
			"--description", "Cmd test description",
			"--parent", "organizations/123",
			"--target", "folders/456",
		}
		rootTestCmd.SetArgs(args)

		err := rootTestCmd.Execute()
		require.NoError(t, err, "Cobra command execution failed for success case")

		output := buf.String()
		assert.Contains(t, output, "Successfully created posture files:")
		tfFilePath := filepath.Join("build", "postures", "cmd_test_posture.tf")
		assert.Contains(t, output, tfFilePath)
		_, statErr := os.Stat(tfFilePath)
		assert.NoError(t, statErr, "Terraform file should be created by command at: %s", tfFilePath)
	})

	t.Run("MissingRequiredFlag", func(t *testing.T) {
		_, cleanup := setupTestDir(t)
		defer cleanup()

		testCmd := createTestNewPostureCmd() // Fresh instance
		rootTestCmd := &cobra.Command{Use: "agf-test-root"}
		rootTestCmd.AddCommand(testCmd)

		// Diagnostic: Check if the flag is correctly marked as required on the test instance
		nameFlag := testCmd.Flags().Lookup("name")
		require.NotNil(t, nameFlag, "Flag --name not found on testCmd instance")
		ann, ok := nameFlag.Annotations[cobra.BashCompOneRequiredFlag]
		require.True(t, ok, "BashCompOneRequiredFlag annotation missing for --name")
		require.Equal(t, []string{"true"}, ann, "Annotation for --name not set to 'true'")
		// End Diagnostic

		buf := new(bytes.Buffer)
		rootTestCmd.SetOut(buf) // Capture Stdout
		rootTestCmd.SetErr(buf) // Capture Stderr (where Cobra often prints "required flag" errors)

		args := []string{
			"new-posture", // Command to execute
			// --name is missing
			"--description", "Only desc",
			"--parent", "organizations/789",
			"--target", "projects/101",
		}
		rootTestCmd.SetArgs(args) // Set arguments for the root command

		err := rootTestCmd.Execute()
		// Expect an error because a required flag is missing.
		require.Error(t, err, "Expected an error due to missing required flag '--name'")

		// The error returned by Execute() should be Cobra's specific error for missing required flags.
		assert.Contains(t, err.Error(), `required flag(s) "name" not set`, "Error message from Execute() mismatch")

		// The Stderr buffer should also contain this message from Cobra.
		output := buf.String()
		assert.Contains(t, output, `Error: required flag(s) "name" not set`, "Stderr output mismatch")
		// Cobra also prints usage on such errors.
		assert.Contains(t, output, testCmd.UsageString(), "Usage string should be present in Stderr output")
	})

	t.Run("InvalidFlagValueViaCommand", func(t *testing.T) {
		_, cleanup := setupTestDir(t)
		defer cleanup()

		testCmd := createTestNewPostureCmd()
		rootTestCmd := &cobra.Command{Use: "agf-test-root"}
		rootTestCmd.AddCommand(testCmd)

		buf := new(bytes.Buffer)
		rootTestCmd.SetOut(buf)
		rootTestCmd.SetErr(buf)

		args := []string{
			"new-posture",
			"--name", "invalid-name!", // Invalid char, should be caught by NewPosture's own validation
			"--description", "Desc for invalid name",
			"--parent", "organizations/112",
			"--target", "folders/314",
		}
		rootTestCmd.SetArgs(args)
		err := rootTestCmd.Execute()
		require.Error(t, err, "Expected an error due to invalid flag value format for --name")

		// The error should come from NewPosture's validation, propagated by RunE.
		assert.Contains(t, err.Error(), "name 'invalid-name!' is invalid", "Error message from NewPosture validation mismatch")

		// Cobra typically prints "Error: <err.Error()>\n" and then the usage to Stderr.
		output := buf.String()
		assert.Contains(t, output, "Error: name 'invalid-name!' is invalid", "Stderr output mismatch for invalid flag value")
		assert.Contains(t, output, testCmd.UsageString(), "Usage string should be present in Stderr for invalid flag value")
	})
}
