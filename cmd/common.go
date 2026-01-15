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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// Declare function variables here to replace os and filesystem functions.
// This allows afero to mock the filesystem for unit testing.
// These are used to test any functionality that directly integrates with the filesystem.
var (
	osReadFile   func(name string) ([]byte, error)                      = os.ReadFile
	osWriteFile  func(name string, data []byte, perm os.FileMode) error = os.WriteFile
	osCreateFile func(name string) (*os.File, error)                    = os.Create
	osReadDir    func(name string) ([]os.DirEntry, error)               = os.ReadDir
	filepathWalk func(root string, walkFn filepath.WalkFunc) error      = filepath.Walk
	osMkdirAll   func(path string, perm os.FileMode) error              = os.MkdirAll
	osRemoveFile func(name string) error                                = os.Remove
)

// Helper function to set up the mock filesystem and function variables for a test.
// It returns a cleanup function to restore the original variables.
func setupTestEnvironment(t *testing.T) func() {
	// Store original functions from the cmd package
	originalReadFile := osReadFile
	originalCreateFile := osCreateFile // Keep track of original os.Create
	originalMkdirAll := osMkdirAll
	originalRemoveFile := osRemoveFile
	originalFilepathWalk := filepathWalk

	// Setup mock filesystem
	MockFs = afero.NewMemMapFs()

	// Override functions to use afero for reads, dir creation, removal, walk
	osReadFile = func(name string) ([]byte, error) {
		return afero.ReadFile(MockFs, name)
	}
	osMkdirAll = func(path string, perm os.FileMode) error {
		return MockFs.MkdirAll(path, perm)
	}
	osRemoveFile = func(name string) error {
		return MockFs.Remove(name)
	}
	filepathWalk = func(root string, walkFn filepath.WalkFunc) error {
		return afero.Walk(MockFs, root, walkFn)
	}
	// createFile remains untouched globally, defaulting to os.Create
	// Tests needing specific behavior will handle it.
	osCreateFile = os.Create

	// Return cleanup function
	return func() {
		osReadFile = originalReadFile
		osCreateFile = originalCreateFile // Restore original os.Create
		osMkdirAll = originalMkdirAll
		osRemoveFile = originalRemoveFile
		filepathWalk = originalFilepathWalk
		MockFs = nil // Clear the mock filesystem
	}
}

// MockFs is an in-memory filesystem for testing.
var MockFs afero.Fs

// Helper to reset and use mock filesystem for relevant os functions
func setupMockFs() {
	MockFs = afero.NewMemMapFs()
	// Override the function variables (which should be defined in main.go)
	osReadFile = func(filename string) ([]byte, error) {
		return afero.ReadFile(MockFs, filename)
	}
	osWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		return afero.WriteFile(MockFs, filename, data, perm)
	}
	osReadDir = func(name string) ([]os.DirEntry, error) {
		// afero.ReadDir returns []os.FileInfo, but we need []os.DirEntry
		// to match the signature of os.ReadDir (Go 1.16+).
		fileInfos, err := afero.ReadDir(MockFs, name)
		if err != nil {
			return nil, err
		}
		dirEntries := make([]os.DirEntry, 0, len(fileInfos))
		for _, fi := range fileInfos {
			// os.FileInfoToDirEntry converts an os.FileInfo to an os.DirEntry.
			// This function was added in Go 1.17. os.DirEntry was added in 1.16.
			dirEntries = append(dirEntries, fs.FileInfoToDirEntry(fi))
		}
		return dirEntries, nil
	}
	// For filepathWalk, it's more complex to directly mock with afero's Walk.
	// Tests for main() will mock filepathWalk directly if needed for very specific scenarios,
	// or rely on the fact that filepathWalk itself will use the mocked osReadFile/readDir.
}

// Helper function to create a mock file with content using afero
func createMockFile(t *testing.T, fs afero.Fs, path string, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	// Ensure directory exists in the mock filesystem
	err := fs.MkdirAll(dir, 0755)
	require.NoError(t, err, "Failed to create mock directory %s", dir)
	// Write the file
	err = afero.WriteFile(fs, path, []byte(content), 0644)
	require.NoError(t, err, "Failed to write mock file %s", path)
}

// createTempDir is a helper function to create a temporary directory for testing.
// It ensures the directory is cleaned up after the test.
func createTempDir(t *testing.T, prefix string) string {
	t.Helper() // Marks this function as a test helper
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	return dir
}

// createTempFile is a helper function to create a temporary file with content.
func createTempFile(t *testing.T, dir, filename, content string) string {
	t.Helper()
	filePath := filepath.Join(dir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file %s: %v", filePath, err)
	}
	return filePath
}

// Read a metadata file and extract the data, casting as *Metadata
func extractMetadata(metadataFile string) (*Metadata, error) {
	// Read the metadata.yaml file
	data, err := osReadFile(metadataFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file %s: %w", metadataFile, err)
	}

	// Parse the YAML data
	var metadata Metadata
	err = yaml.Unmarshal(data, &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metadata file %s: %w", metadataFile, err)
	}

	// Validate required keys
	// TODO: Work to determine the necessity of this check in the metadata extraction function
	if metadata.PolicyID == "" || metadata.Description == "" || len(metadata.Postures) == 0 {
		return nil, fmt.Errorf("invalid metadata in %s: missing required keys", metadataFile)
	}

	return &metadata, nil
}

// Convert hclwrite Tokens to string counterparts
func tokensToString(tokens hclwrite.Tokens) string {
	var sb strings.Builder
	for _, token := range tokens {
		sb.WriteString(string(token.Bytes))
	}
	return strings.Trim(sb.String(), "\"")
}
