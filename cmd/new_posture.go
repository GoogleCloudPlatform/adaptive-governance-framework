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
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big" // Required for crypto/rand.Int
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

// newPostureCmd represents the new command
var newPostureCmd = &cobra.Command{
	Use:   "new-posture",
	Short: "Creates the necessary files for a new security posture.",
	Long: `Creates a Terraform file for defining a new Google Cloud Security Posture
and its associated deployment resource.

Example:
  agf new-posture --name my_org_posture --description "Main organizational posture" --parent organizations/12345 --target organizations/12345`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Fetch flag values directly from the command's flags collection for robustness.
		nameVal, err := cmd.Flags().GetString("name")
		if err != nil {
			// This should ideally not happen if flags are defined correctly.
			return fmt.Errorf("error getting name flag: %w", err)
		}
		descVal, err := cmd.Flags().GetString("description")
		if err != nil {
			return fmt.Errorf("error getting description flag: %w", err)
		}
		parentVal, err := cmd.Flags().GetString("parent")
		if err != nil {
			return fmt.Errorf("error getting parent flag: %w", err)
		}
		targetVal, err := cmd.Flags().GetString("target")
		if err != nil {
			return fmt.Errorf("error getting target flag: %w", err)
		}

		// Pass cmd.OutOrStdout() for output, and the fetched flag values.
		return NewPosture(cmd.OutOrStdout(), nameVal, descVal, parentVal, targetVal)
	},
}

// Global variables to hold the flag values. Cobra populates these.
var Name, Description, Parent, Target string

func init() {
	// Define flags and bind them to the global variables.
	newPostureCmd.Flags().StringVarP(&Name, "name", "n", "", "The name for the Terraform posture file (alphanumeric + underscore, e.g., 'folder_b_posture') (required)")
	newPostureCmd.Flags().StringVarP(&Description, "description", "d", "", "The description for the posture resource (required)")
	newPostureCmd.Flags().StringVarP(&Parent, "parent", "p", "", "The organization/folder/project node where the posture resource itself will be created. E.g., organizations/123. (required)")
	newPostureCmd.Flags().StringVarP(&Target, "target", "t", "", "The hierarchy node this posture will target for deployment. E.g., organizations/123, folders/123, projects/123. (required)")

	// Mark flags as required. Cobra will handle enforcement.
	err := newPostureCmd.MarkFlagRequired("name")
	if err != nil {
		log.Fatalf("Failed to mark 'name' flag required: %v", err) // This log.Fatalf is at init time, generally acceptable
	}
	err = newPostureCmd.MarkFlagRequired("description")
	if err != nil {
		log.Fatalf("Failed to mark 'description' flag required: %v", err)
	}
	err = newPostureCmd.MarkFlagRequired("parent")
	if err != nil {
		log.Fatalf("Failed to mark 'parent' flag required: %v", err)
	}
	err = newPostureCmd.MarkFlagRequired("target")
	if err != nil {
		log.Fatalf("Failed to mark 'target' flag required: %v", err)
	}

	rootCmd.AddCommand(newPostureCmd)
}

// TemplateData holds the variables needed for template execution
type TemplateData struct {
	Name                string
	NameWithHyphens     string
	Description         string
	Parent              string
	Target              string
	RandomIdForResource string
}

const (
	postureTFTemplate = `############## THIS FILE IS MANAGED BY REPOSITORY AUTOMATION ##############

# PLEASE REFRAIN FROM MAKING MANUAL EDITS TO THIS REPOSITORY
# EXCEPT IN CASES OUTLINED BELOW:

/**
* This Terraform file is responsible for creating the "{{.Name}}" security posture
* and deploying it to "{{.Parent}}" with a posture deployment resource.
*
* Please do not manually edit the "google_securityposture_posture" resource. It may be necessary upon
* initial setup to import any existing posture resources and posture deployment resources as such:
*
* import {
* id = "{{.Parent}}/locations/global/postures/{{.NameWithHyphens}}"
* to = google_securityposture_posture.default
* }
*
*/

# Terraform documentation: https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/securityposture_posture

####################### POSTURE DEPLOYMENT SECTION: #######################

# Create a new posture deployment ID each time we update the posture
resource "random_id" "{{.RandomIdForResource}}" {
  keepers = {
    # Generate a new id each time we update the posture
    posture_revision_id = google_securityposture_posture.{{.Name}}.revision_id
  }
  byte_length = 4
}

# Create the posture deployment
resource "google_securityposture_posture_deployment" "{{.Name}}_deployment" {
  location              = "global"
  parent                = "{{.Parent}}" # This should be the parent for the *deployment*, typically same as posture target.
  posture_deployment_id = "deployment-${google_securityposture_posture.{{.Name}}.revision_id}-${random_id.{{.RandomIdForResource}}.hex}"
  posture_id            = google_securityposture_posture.{{.Name}}.id
  posture_revision_id   = google_securityposture_posture.{{.Name}}.revision_id
  target_resource       = "{{.Target}}"

  depends_on = [google_securityposture_posture.{{.Name}}]
}

##################### NO MANUAL EDITS BELOW THIS LINE #####################

resource "google_securityposture_posture" "{{.Name}}" {
  posture_id  = "{{.NameWithHyphens}}"
  parent      = "{{.Parent}}" # This is the parent for the posture resource itself.
  location    = "global"
  state       = "ACTIVE" # Or "DEPRECATED"
  description = "{{.Description}}"

  policy_sets {}
}
`
)

var postureNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
var parentRegex = regexp.MustCompile(`^organizations/\d+$`)
var targetRegex = regexp.MustCompile(`^(organizations|folders|projects)/\d+$`)

// createFileFromTemplate generates a file from a Go text template
func createFileFromTemplate(filePath, templateName, templateContent string, data TemplateData) error {
	_, err := os.Stat(filePath)
	if err == nil {
		log.Printf("Skipping creation: File '%s' already exists.", filePath) // Uses global log
		return nil                                                           // Or an error indicating skipped
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking file '%s': %w", filePath, err)
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating directory '%s': %w", dir, err)
	}
	log.Printf("Ensured directory exists: %s", dir)

	tmpl, err := template.New(templateName).Parse(templateContent)
	if err != nil {
		return fmt.Errorf("error parsing template '%s': %w", templateName, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("error executing template '%s': %w", templateName, err)
	}

	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("error writing file '%s': %w", filePath, err)
	}
	log.Printf("Created file: %s", filePath) 
	return nil
}

func generateRandomLetterID(length int) (string, error) {
	const letterCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if length <= 0 {
		return "", fmt.Errorf("letter ID length must be a positive integer")
	}
	var sb strings.Builder
	sb.Grow(length)
	charsetLen := big.NewInt(int64(len(letterCharset)))
	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random index for letter ID: %w", err)
		}
		sb.WriteByte(letterCharset[randomIndex.Int64()])
	}
	return sb.String(), nil
}

// NewPosture contains the core logic for creating posture files.
// It accepts an io.Writer for its output and returns errors for validation.
func NewPosture(out io.Writer, name string, description string, parent string, target string) error {
	// --- Validate Input Formats (Presence should be handled by Cobra's MarkFlagRequired) ---
	if !postureNameRegex.MatchString(name) {
		return fmt.Errorf("name '%s' is invalid. It must contain only alphanumeric characters and underscores", name)
	}
	if !parentRegex.MatchString(parent) {
		return fmt.Errorf("parent '%s' is invalid. Expected format like 'organizations/NUMBER'. This is for the posture resource itself", parent)
	}
	if !targetRegex.MatchString(target) {
		return fmt.Errorf("target '%s' is invalid. Expected format like '(organizations|folders|projects)/NUMBER'. This is for the posture deployment", target)
	}

	posturesDir := filepath.Join("build", "postures")
	tfFilePath := filepath.Join(posturesDir, fmt.Sprintf("%s.tf", name))

	hexID, err := generateRandomLetterID(8)
	if err != nil {
		// Propagate error instead of log.Fatalf
		return fmt.Errorf("error generating random ID: %w", err)
	}

	data := TemplateData{
		Name:                name,
		NameWithHyphens:     strings.ReplaceAll(name, "_", "-"),
		Description:         description,
		Parent:              parent,
		Target:              target,
		RandomIdForResource: hexID,
	}

	// createFileFromTemplate now returns an error
	if err := createFileFromTemplate(tfFilePath, "posture.tf", postureTFTemplate, data); err != nil {
		return err // Propagate error
	}

	// Use the provided io.Writer for output
	fmt.Fprintln(out, "\nSuccessfully created posture files:")
	fmt.Fprintf(out, "- %s\n", tfFilePath)
	fmt.Fprintln(out, "\nReminder: Ensure the 'parent' attribute in the generated .tf file for the posture resource and the posture deployment are accurate for your use case.")
	return nil
}
