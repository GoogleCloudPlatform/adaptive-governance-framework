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

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateNewPolicyBlock_SHA(t *testing.T) {
	policy := &Policy{
		PolicyID: "sha-policy-1",
		Constraint: &Constraint{
			SHAModule: &SHAModule{
				ModuleName:            "FORSETI_SECURITY_HEALTH_ANALYTICS_MODULE",
				ModuleEnablementState: "ENABLED",
			},
		},
	}
	metadata := &Metadata{
		PolicyID:    "sha-policy-1",
		Description: "Test SHA Policy",
		ComplianceStandards: []struct {
			Standard string `yaml:"standard"`
			Control  string `yaml:"control"`
		}{
			{Standard: "CIS_1_2", Control: "3.1"},
		},
	}

	block, err := createNewPolicyBlock(policy, metadata, "sha")
	require.NoError(t, err)
	require.NotNil(t, block)

	// Basic checks
	assert.Equal(t, "policy_sets", block.Type())
	assert.Equal(t, "sha_policy_set", tokensToString(block.Body().GetAttribute("policy_set_id").Expr().BuildTokens(nil)))

	policiesBlocks := block.Body().Blocks()
	require.Len(t, policiesBlocks, 1)
	policyInnerBlock := policiesBlocks[0]
	assert.Equal(t, "policies", policyInnerBlock.Type())
	assert.Equal(t, "sha-policy-1", tokensToString(policyInnerBlock.Body().GetAttribute("policy_id").Expr().BuildTokens(nil)))
	assert.Equal(t, "Test SHA Policy", tokensToString(policyInnerBlock.Body().GetAttribute("description").Expr().BuildTokens(nil)))

	constraintBlock := policyInnerBlock.Body().Blocks()[0] // First block is constraint
	require.Equal(t, "constraint", constraintBlock.Type())
	shaModuleBlock := constraintBlock.Body().Blocks()[0]
	require.Equal(t, "security_health_analytics_module", shaModuleBlock.Type())
	assert.Equal(t, "FORSETI_SECURITY_HEALTH_ANALYTICS_MODULE", tokensToString(shaModuleBlock.Body().GetAttribute("module_name").Expr().BuildTokens(nil)))
	assert.Equal(t, "ENABLED", tokensToString(shaModuleBlock.Body().GetAttribute("module_enablement_state").Expr().BuildTokens(nil)))

	var complianceStandardBlocks []*hclwrite.Block
	for _, b := range policyInnerBlock.Body().Blocks() {
		if b.Type() == "compliance_standards" {
			complianceStandardBlocks = append(complianceStandardBlocks, b)
		}
	}
	require.Len(t, complianceStandardBlocks, 1, "Expected one compliance_standards block")
	csBlock := complianceStandardBlocks[0]
	assert.Equal(t, "CIS_1_2", tokensToString(csBlock.Body().GetAttribute("standard").Expr().BuildTokens(nil)))
	assert.Equal(t, "3.1", tokensToString(csBlock.Body().GetAttribute("control").Expr().BuildTokens(nil)))

	// Test missing SHAModule data
	policyMissing := &Policy{PolicyID: "sha-policy-2", Constraint: &Constraint{}}
	_, err = createNewPolicyBlock(policyMissing, metadata, "sha")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing SHAModule data for SHA policy")
}

func TestCreateNewPolicyBlock_CustomSHA(t *testing.T) {
	// --- Test Data with Slice of Properties ---
	policy := &Policy{
		PolicyID: "custom-sha-policy-1",
		Constraint: &Constraint{
			CustomSHAModule: &CustomSHAModule{
				DisplayName: "My Custom SHA Detector",
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
					}{"resource.type == 'storage.googleapis.com/Bucket'"},
					CustomOutput: &struct {
						Properties []struct {
							Name            string `yaml:"name"`
							ValueExpression struct {
								Expression string `yaml:"expression"`
							} `yaml:"valueExpression"`
						} `yaml:"properties"`
					}{
						Properties: []struct {
							Name            string `yaml:"name"`
							ValueExpression struct {
								Expression string `yaml:"expression"`
							} `yaml:"valueExpression"`
						}{
							{Name: "location", ValueExpression: struct {
								Expression string `yaml:"expression"`
							}{"resource.location"}},
							{Name: "storageClass", ValueExpression: struct {
								Expression string `yaml:"expression"`
							}{"resource.storageClass"}},
						},
					},
					ResourceSelector: &struct {
						ResourceTypes []string `yaml:"resourceTypes"`
					}{ResourceTypes: []string{"storage.googleapis.com/Bucket"}},
					Severity:       "HIGH",
					Description:    "Detects public buckets.",
					Recommendation: "Make buckets private.",
				},
				ModuleEnablementState: "ENABLED",
			},
		},
	}
	metadata := &Metadata{PolicyID: "custom-sha-policy-1", Description: "Test Custom SHA Policy"}

	block, err := createNewPolicyBlock(policy, metadata, "customsha")
	require.NoError(t, err)
	require.NotNil(t, block)

	assert.Equal(t, "customsha_policy_set", tokensToString(block.Body().GetAttribute("policy_set_id").Expr().BuildTokens(nil)))
	policyInnerBlock := block.Body().Blocks()[0] // policies block

	var constraintBlock *hclwrite.Block
	for _, b := range policyInnerBlock.Body().Blocks() {
		if b.Type() == "constraint" {
			constraintBlock = b
			break
		}
	}
	require.NotNil(t, constraintBlock, "constraint block not found")
	customShaConstraintBlock := constraintBlock.Body().Blocks()[0] // security_health_analytics_custom_module

	require.Equal(t, "security_health_analytics_custom_module", customShaConstraintBlock.Type())
	assert.Equal(t, "My Custom SHA Detector", tokensToString(customShaConstraintBlock.Body().GetAttribute("display_name").Expr().BuildTokens(nil)))
	assert.Equal(t, "ENABLED", tokensToString(customShaConstraintBlock.Body().GetAttribute("module_enablement_state").Expr().BuildTokens(nil)))

	configBlock := customShaConstraintBlock.Body().Blocks()[0] // First block is config
	require.Equal(t, "config", configBlock.Type())
	assert.Equal(t, "Detects public buckets.", tokensToString(configBlock.Body().GetAttribute("description").Expr().BuildTokens(nil)))
	assert.Equal(t, "HIGH", tokensToString(configBlock.Body().GetAttribute("severity").Expr().BuildTokens(nil)))
	assert.Equal(t, "Make buckets private.", tokensToString(configBlock.Body().GetAttribute("recommendation").Expr().BuildTokens(nil)))

	var predicateBlock, customOutputBlockFound, resourceSelectorBlockFound *hclwrite.Block
	for _, b := range configBlock.Body().Blocks() {
		switch b.Type() {
		case "predicate":
			predicateBlock = b
		case "custom_output":
			customOutputBlockFound = b
		case "resource_selector":
			resourceSelectorBlockFound = b
		}
	}
	require.NotNil(t, predicateBlock, "predicate block not found in config")
	require.NotNil(t, customOutputBlockFound, "custom_output block not found in config")
	require.NotNil(t, resourceSelectorBlockFound, "resource_selector block not found in config")

	assert.Equal(t, "resource.type == 'storage.googleapis.com/Bucket'", tokensToString(predicateBlock.Body().GetAttribute("expression").Expr().BuildTokens(nil)))

	propertiesBlocks := customOutputBlockFound.Body().Blocks()
	require.Len(t, propertiesBlocks, 2, "Expected 2 'properties' blocks within 'custom_output'")

	prop1Block := propertiesBlocks[0]
	assert.Equal(t, "properties", prop1Block.Type())
	assert.Equal(t, "location", tokensToString(prop1Block.Body().GetAttribute("name").Expr().BuildTokens(nil)))
	valueExpr1Block := prop1Block.Body().Blocks()[0]
	assert.Equal(t, "value_expression", valueExpr1Block.Type())
	assert.Equal(t, "resource.location", tokensToString(valueExpr1Block.Body().GetAttribute("expression").Expr().BuildTokens(nil)))

	prop2Block := propertiesBlocks[1]
	assert.Equal(t, "properties", prop2Block.Type())
	assert.Equal(t, "storageClass", tokensToString(prop2Block.Body().GetAttribute("name").Expr().BuildTokens(nil)))
	valueExpr2Block := prop2Block.Body().Blocks()[0]
	assert.Equal(t, "value_expression", valueExpr2Block.Type())
	assert.Equal(t, "resource.storageClass", tokensToString(valueExpr2Block.Body().GetAttribute("expression").Expr().BuildTokens(nil)))

	resourceTypesAttr := resourceSelectorBlockFound.Body().GetAttribute("resource_types")
	if len(policy.Constraint.CustomSHAModule.Config.ResourceSelector.ResourceTypes) > 0 {
		require.NotNil(t, resourceTypesAttr, "resource_types attribute should exist")
		assert.Contains(t, string(resourceTypesAttr.Expr().BuildTokens(nil).Bytes()), "storage.googleapis.com/Bucket")
	} else {
		assert.Nil(t, resourceTypesAttr, "resource_types attribute should be omitted if list is empty")
	}

	// Test missing CustomSHAModule data
	policyMissing := &Policy{PolicyID: "custom-sha-2", Constraint: &Constraint{}}
	_, err = createNewPolicyBlock(policyMissing, metadata, "customsha")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing CustomSHAModule data for custom SHA policy")

	// --- Test CustomOutput being nil ---
	policyNoOutput := &Policy{
		PolicyID: "custom-sha-no-output",
		Constraint: &Constraint{CustomSHAModule: &CustomSHAModule{
			DisplayName: "No Output",
			// Use the full anonymous struct type definition here
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
				// CustomOutput remains nil here by not initializing it
				// ResourceSelector also remains nil
				Severity:    "LOW",
				Description: "Desc",
			},
			ModuleEnablementState: "ENABLED",
		}},
	}
	blockNoOutput, errNoOutput := createNewPolicyBlock(policyNoOutput, &Metadata{PolicyID: "custom-sha-no-output"}, "customsha")
	require.NoError(t, errNoOutput)
	// Navigate safely: policy_sets -> policies -> constraint -> custom_sha -> config
	policySetBody := blockNoOutput.Body()
	require.NotNil(t, policySetBody)
	policiesBlocks := policySetBody.Blocks()
	require.Len(t, policiesBlocks, 1)
	policyInnerBody := policiesBlocks[0].Body()
	require.NotNil(t, policyInnerBody)
	var constraintBlockNoOutput *hclwrite.Block
	for _, b := range policyInnerBody.Blocks() {
		if b.Type() == "constraint" {
			constraintBlockNoOutput = b
			break
		}
	}
	require.NotNil(t, constraintBlockNoOutput)
	constraintBody := constraintBlockNoOutput.Body()
	require.NotNil(t, constraintBody)
	customShaBlocks := constraintBody.Blocks()
	require.Len(t, customShaBlocks, 1)
	customShaBody := customShaBlocks[0].Body()
	require.NotNil(t, customShaBody)
	var configBlockNoOutput *hclwrite.Block
	for _, b := range customShaBody.Blocks() {
		if b.Type() == "config" {
			configBlockNoOutput = b
			break
		}
	}
	require.NotNil(t, configBlockNoOutput)

	// Now check within the config block
	configBodyNoOutput := configBlockNoOutput.Body()
	require.NotNil(t, configBodyNoOutput)
	var customOutputBlockNil *hclwrite.Block
	for _, b := range configBodyNoOutput.Blocks() {
		if b.Type() == "custom_output" {
			customOutputBlockNil = b
			break
		}
	}
	assert.Nil(t, customOutputBlockNil, "custom_output block should be nil when source CustomOutput is nil")
}

func TestCreateNewPolicyBlock_OrgPolicy(t *testing.T) {
	policy := &Policy{
		PolicyID: "org-policy-1",
		Constraint: &Constraint{
			OrgPolicyConstraint: &OrgPolicyConstraint{
				CannedConstraintID: "constraints/serviceuser.services",
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
				}{
					{ // Rule 1: ListPolicy with allowed_values and DENIED_VALUES IS NIL (will be omitted)
						ListPolicy: &struct {
							AllowedValues     []string `yaml:"allowedValues"`
							DeniedValues      []string `yaml:"deniedValues"`
							InheritFromParent bool     `yaml:"inheritFromParent"`
							SuggestedValue    string   `yaml:"suggestedValue"`
						}{
							AllowedValues:     []string{"bigquery.googleapis.com"},
							DeniedValues:      nil, // Explicitly nil, createStringVals should return empty non-nil, but workaround might omit attr
							InheritFromParent: true,
						},
					},
					{ // Rule 2: DenyAll
						DenyAll: true,
						ListPolicy: &struct {
							AllowedValues     []string `yaml:"allowedValues"`
							DeniedValues      []string `yaml:"deniedValues"`
							InheritFromParent bool     `yaml:"inheritFromParent"`
							SuggestedValue    string   `yaml:"suggestedValue"`
						}{
							AllowedValues: []string{}, // Empty, createStringVals -> empty non-nil, workaround might omit attr
							DeniedValues:  []string{}, // Empty, createStringVals -> empty non-nil, workaround might omit attr
						},
					},
				},
			},
		},
	}
	metadata := &Metadata{PolicyID: "org-policy-1", Description: "Test Org Policy"}

	block, err := createNewPolicyBlock(policy, metadata, "orgpolicy")
	require.NoError(t, err)
	require.NotNil(t, block)

	policyInnerBlock := block.Body().Blocks()[0]
	var constraintBlock *hclwrite.Block
	for _, b := range policyInnerBlock.Body().Blocks() {
		if b.Type() == "constraint" {
			constraintBlock = b
			break
		}
	}
	require.NotNil(t, constraintBlock, "constraint block not found")
	orgPolicyConstraintBlock := constraintBlock.Body().Blocks()[0]

	var policyRuleBlocks []*hclwrite.Block
	for _, b := range orgPolicyConstraintBlock.Body().Blocks() {
		if b.Type() == "policy_rules" {
			policyRuleBlocks = append(policyRuleBlocks, b)
		}
	}
	require.Len(t, policyRuleBlocks, 2, "Expected 2 policy_rules blocks")

	// Rule 1 Checks
	rule1Block := policyRuleBlocks[0]
	var listPolicyBlockRule1 *hclwrite.Block
	for _, b := range rule1Block.Body().Blocks() {
		if b.Type() == "list_policy" {
			listPolicyBlockRule1 = b
			break
		}
	}
	require.NotNil(t, listPolicyBlockRule1, "list_policy block for rule 1 not found")

	// Check allowed_values (should exist)
	allowedValuesAttrRule1 := listPolicyBlockRule1.Body().GetAttribute("allowed_values")
	require.NotNil(t, allowedValuesAttrRule1, "allowed_values for rule 1 should exist")
	assert.Contains(t, string(allowedValuesAttrRule1.Expr().BuildTokens(nil).Bytes()), "bigquery.googleapis.com")

	// Check denied_values (SHOULD BE OMITTED by workaround because input was nil)
	deniedValuesAttrRule1 := listPolicyBlockRule1.Body().GetAttribute("denied_values")
	assert.Nil(t, deniedValuesAttrRule1, "denied_values for rule 1 should be nil (omitted by workaround)")

	// Check inherit_from_parent
	inheritAttrRule1 := listPolicyBlockRule1.Body().GetAttribute("inherit_from_parent")
	require.NotNil(t, inheritAttrRule1)
	inheritValRule1 := inheritAttrRule1.Expr().BuildTokens(nil)
	assert.Equal(t, "true", tokensToString(inheritValRule1))

	// --- Rule 2 Checks ---
	rule2Block := policyRuleBlocks[1]
	// Check DenyAll (should exist and be true)
	denyAllAttrRule2 := rule2Block.Body().GetAttribute("deny_all")
	require.NotNil(t, denyAllAttrRule2, "deny_all for rule 2 not found")
	denyAllValRule2 := denyAllAttrRule2.Expr().BuildTokens(nil)
	assert.Equal(t, "true", tokensToString(denyAllValRule2), "deny_all for rule 2 should be true")

	// Check for list_policy block (SHOULD NOT EXIST for Rule 2 because DenyAll is true)
	var listPolicyBlockRule2 *hclwrite.Block
	for _, b := range rule2Block.Body().Blocks() {
		if b.Type() == "list_policy" {
			listPolicyBlockRule2 = b
			break
		}
	}
	assert.Nil(t, listPolicyBlockRule2, "list_policy block for rule 2 should be nil (omitted because DenyAll is true)")
}

func TestCreateNewPolicyBlock_CustomOrgPolicy(t *testing.T) {
	policy := &Policy{
		PolicyID: "custom-org-policy-1",
		Constraint: &Constraint{
			CustomOrgPolicyConstraint: &CustomOrgPolicyConstraint{
				CustomConstraint: struct {
					Name          string   `yaml:"name"`
					DisplayName   string   `yaml:"displayName"`
					Description   string   `yaml:"description"`
					ActionType    string   `yaml:"actionType"`
					Condition     string   `yaml:"condition"`
					MethodTypes   []string `yaml:"methodTypes"`
					ResourceTypes []string `yaml:"resourceTypes"`
				}{
					Name:          "organizations/123/customConstraints/custom.myRule",
					DisplayName:   "My Custom Org Rule",
					Description:   "Enforces custom org behavior.",
					ActionType:    "ALLOW",
					Condition:     "resource.location == 'us-central1'",
					MethodTypes:   []string{"CREATE"},
					ResourceTypes: []string{"compute.googleapis.com/Instance"},
				},
				PolicyRules: []struct {
					Enforce   bool `yaml:"enforce"` // This will be asserted
					Condition *struct {
						Description string `yaml:"description"`
						Expression  string `yaml:"expression"`
						Title       string `yaml:"title"`
					} `yaml:"condition,omitempty"`
				}{
					{
						Enforce: true, // Assert this is true
						Condition: &struct {
							Description string `yaml:"description"`
							Expression  string `yaml:"expression"`
							Title       string `yaml:"title"`
						}{
							Description: "Condition for custom rule",
							Expression:  "true", // Simplified
							Title:       "Custom Rule Condition",
						},
					},
					{
						Enforce: false, // Assert this is false
					},
				},
			},
		},
	}
	metadata := &Metadata{
		PolicyID:    "custom-org-policy-1",
		Description: "Test Custom Org Policy",
	}

	block, err := createNewPolicyBlock(policy, metadata, "customorgpolicy")
	require.NoError(t, err)
	require.NotNil(t, block)

	assert.Equal(t, "customorgpolicy_policy_set", tokensToString(block.Body().GetAttribute("policy_set_id").Expr().BuildTokens(nil)))
	policyInnerBlock := block.Body().Blocks()[0] // policies block

	var constraintBlock *hclwrite.Block
	for _, b := range policyInnerBlock.Body().Blocks() {
		if b.Type() == "constraint" {
			constraintBlock = b
			break
		}
	}
	require.NotNil(t, constraintBlock, "constraint block not found")
	customOrgConstraintBlock := constraintBlock.Body().Blocks()[0] // org_policy_constraint_custom

	require.Equal(t, "org_policy_constraint_custom", customOrgConstraintBlock.Type())

	var innerCustomConstraintBlock *hclwrite.Block
	var policyRuleBlocks []*hclwrite.Block

	for _, b := range customOrgConstraintBlock.Body().Blocks() {
		if b.Type() == "custom_constraint" {
			innerCustomConstraintBlock = b
		} else if b.Type() == "policy_rules" {
			policyRuleBlocks = append(policyRuleBlocks, b)
		}
	}
	require.NotNil(t, innerCustomConstraintBlock, "custom_constraint block not found")
	require.Len(t, policyRuleBlocks, 2, "Expected 2 policy_rules blocks")

	assert.Equal(t, "organizations/123/customConstraints/custom.myRule", tokensToString(innerCustomConstraintBlock.Body().GetAttribute("name").Expr().BuildTokens(nil)))
	assert.Equal(t, "My Custom Org Rule", tokensToString(innerCustomConstraintBlock.Body().GetAttribute("display_name").Expr().BuildTokens(nil)))
	assert.Equal(t, "Enforces custom org behavior.", tokensToString(innerCustomConstraintBlock.Body().GetAttribute("description").Expr().BuildTokens(nil)))
	assert.Equal(t, "ALLOW", tokensToString(innerCustomConstraintBlock.Body().GetAttribute("action_type").Expr().BuildTokens(nil)))
	assert.Equal(t, "resource.location == 'us-central1'", tokensToString(innerCustomConstraintBlock.Body().GetAttribute("condition").Expr().BuildTokens(nil)))
	assert.Contains(t, string(innerCustomConstraintBlock.Body().GetAttribute("method_types").Expr().BuildTokens(nil).Bytes()), "CREATE")
	assert.Contains(t, string(innerCustomConstraintBlock.Body().GetAttribute("resource_types").Expr().BuildTokens(nil).Bytes()), "compute.googleapis.com/Instance")

	// Rule 1
	rule1Block := policyRuleBlocks[0] // First policy_rules block
	enforce1Val := rule1Block.Body().GetAttribute("enforce").Expr().BuildTokens(nil)
	assert.Equal(t, "true", tokensToString(enforce1Val))

	conditionBlockForRule1 := rule1Block.Body().Blocks()[0] // condition
	assert.Equal(t, "condition", conditionBlockForRule1.Type())
	assert.Equal(t, "Condition for custom rule", tokensToString(conditionBlockForRule1.Body().GetAttribute("description").Expr().BuildTokens(nil)))

	// Rule 2
	rule2Block := policyRuleBlocks[1] // Second policy_rules block
	enforce2Val := rule2Block.Body().GetAttribute("enforce").Expr().BuildTokens(nil)
	assert.Equal(t, "false", tokensToString(enforce2Val)) // Check for false
	assert.Empty(t, rule2Block.Body().Blocks(), "Expected no condition block for rule 2")

	// Test missing CustomOrgPolicyConstraint data
	policyMissing := &Policy{PolicyID: "custom-org-2", Constraint: &Constraint{}}
	_, err = createNewPolicyBlock(policyMissing, metadata, "customorgpolicy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing CustomOrgPolicyConstraint data for custom org policy")
}

func TestCreateNewPolicyBlock_UnknownType(t *testing.T) {
	policy := &Policy{PolicyID: "unknown-1"}
	metadata := &Metadata{PolicyID: "unknown-1", Description: "Unknown"}
	_, err := createNewPolicyBlock(policy, metadata, "unknowntype")
	require.Error(t, err)
	assert.EqualError(t, err, "unknown policy type: unknowntype")
}
