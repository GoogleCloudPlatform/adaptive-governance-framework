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

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func createNewPolicyBlock(policy *Policy, metadata *Metadata, policyType string) (*hclwrite.Block, error) {
	// Create a new policy_set block
	policySetID := fmt.Sprintf("%s_policy_set", policyType)
	newPolicySet := hclwrite.NewBlock("policy_sets", nil)
	newPolicySet.Body().SetAttributeValue("policy_set_id", cty.StringVal(policySetID))
	newPolicySet.Body().SetAttributeValue("description", cty.StringVal(fmt.Sprintf("::DO NOT EDIT::Policy Set for only %s policies, auto-inlined from repository.", policyType)))

	policyBlock := hclwrite.NewBlock("policies", nil)
	policyBlock.Body().SetAttributeValue("policy_id", cty.StringVal(metadata.PolicyID))
	constraintBlock := policyBlock.Body().AppendNewBlock("constraint", nil)

	// Choose the correct constraint block type and populate based on policyType
	switch policyType {
	case "sha":
		if policy.Constraint.SHAModule == nil {
			return nil, fmt.Errorf("missing SHAModule data for SHA policy %s", metadata.PolicyID)
		}
		shaConstraintBlock := constraintBlock.Body().AppendNewBlock("security_health_analytics_module", nil)
		shaConstraintBlock.Body().SetAttributeValue("module_name", cty.StringVal(policy.Constraint.SHAModule.ModuleName))
		shaConstraintBlock.Body().SetAttributeValue("module_enablement_state", cty.StringVal(policy.Constraint.SHAModule.ModuleEnablementState))

	case "customsha":
		if policy.Constraint.CustomSHAModule == nil {
			return nil, fmt.Errorf("missing CustomSHAModule data for custom SHA policy %s", metadata.PolicyID)
		}
		customSHAConstraintBlock := constraintBlock.Body().AppendNewBlock("security_health_analytics_custom_module", nil)
		configBlock := customSHAConstraintBlock.Body().AppendNewBlock("config", nil)

		// Manage predicate block (assuming Predicate itself is never nil based on struct def)
		predicateBlock := configBlock.Body().AppendNewBlock("predicate", nil)
		predicateBlock.Body().SetAttributeValue("expression", cty.StringVal(policy.Constraint.CustomSHAModule.Config.Predicate.Expression))

		// Manage custom_output block - CHECK IF CustomOutput IS NIL FIRST
		if policy.Constraint.CustomSHAModule.Config.CustomOutput != nil && len(policy.Constraint.CustomSHAModule.Config.CustomOutput.Properties) > 0 {
			customOutputBlock := configBlock.Body().AppendNewBlock("custom_output", nil)
			// Iterate over the Properties slice
			for _, prop := range policy.Constraint.CustomSHAModule.Config.CustomOutput.Properties {
				propertiesBlock := customOutputBlock.Body().AppendNewBlock("properties", nil) // Create a properties block for EACH property
				propertiesBlock.Body().SetAttributeValue("name", cty.StringVal(prop.Name))
				// Check if ValueExpression is present (it's a struct, not pointer, so check fields)
				if prop.ValueExpression.Expression != "" {
					valueExpressionBlock := propertiesBlock.Body().AppendNewBlock("value_expression", nil)
					valueExpressionBlock.Body().SetAttributeValue("expression", cty.StringVal(prop.ValueExpression.Expression))
				}
			}
		}

		// Manage resource_selector block - CHECK IF ResourceSelector IS NIL FIRST
		if policy.Constraint.CustomSHAModule.Config.ResourceSelector != nil {
			resourceSelectorBlock := configBlock.Body().AppendNewBlock("resource_selector", nil)
			// Apply workaround for empty lists if needed for resource_types
			resourceTypes := policy.Constraint.CustomSHAModule.Config.ResourceSelector.ResourceTypes
			if len(resourceTypes) > 0 {
				resourceSelectorBlock.Body().SetAttributeValue("resource_types", cty.ListVal(createStringVals(resourceTypes)))
			}
			// Else: omit resource_types if empty, due to cty.ListVal workaround
		}

		// Manage config attributes (These should be safe as Config is not a pointer)
		configBlock.Body().SetAttributeValue("description", cty.StringVal(policy.Constraint.CustomSHAModule.Config.Description))
		configBlock.Body().SetAttributeValue("severity", cty.StringVal(policy.Constraint.CustomSHAModule.Config.Severity))
		// Handle recommendation potentially being empty
		if policy.Constraint.CustomSHAModule.Config.Recommendation != "" {
			configBlock.Body().SetAttributeValue("recommendation", cty.StringVal(policy.Constraint.CustomSHAModule.Config.Recommendation))
		}

		// Manage enablement state & Display Name (These should be safe)
		customSHAConstraintBlock.Body().SetAttributeValue("module_enablement_state", cty.StringVal(policy.Constraint.CustomSHAModule.ModuleEnablementState))
		customSHAConstraintBlock.Body().SetAttributeValue("display_name", cty.StringVal(policy.Constraint.CustomSHAModule.DisplayName))

	case "orgpolicy":
		if policy.Constraint.OrgPolicyConstraint == nil {
			return nil, fmt.Errorf("missing OrgPolicyConstraint data for org policy %s", metadata.PolicyID)
		}
		orgPolicyConstraintBlock := constraintBlock.Body().AppendNewBlock("org_policy_constraint", nil)
		orgPolicyConstraintBlock.Body().SetAttributeValue("canned_constraint_id", cty.StringVal(policy.Constraint.OrgPolicyConstraint.CannedConstraintID))

		// Iterate over PolicyRules
		for _, rule := range policy.Constraint.OrgPolicyConstraint.PolicyRules {
			policyRuleBlock := orgPolicyConstraintBlock.Body().AppendNewBlock("policy_rules", nil)

			// Handle different rule types
			if rule.DenyAll {
				policyRuleBlock.Body().SetAttributeValue("deny_all", cty.BoolVal(true))
			} else if rule.AllowAll {
				policyRuleBlock.Body().SetAttributeValue("allow_all", cty.BoolVal(true))
			} else if rule.ListPolicy != nil {
				listPolicyBlock := policyRuleBlock.Body().AppendNewBlock("list_policy", nil)

				// cty.ListVal tends to panic on empty list input (len == 0),
				// This is a direct workaround to this issue.
				// For now, let's assume omitting is the only way if cty.ListVal(empty) panics.
				// This means the attribute "denied_values" will NOT be present in the HCL if the list is empty.
				deniedCtyValues := createStringVals(rule.ListPolicy.DeniedValues)
				if len(rule.ListPolicy.DeniedValues) > 0 {
					listPolicyBlock.Body().SetAttributeValue("denied_values", cty.ListVal(deniedCtyValues))
				}

				// Do the same for "allowed_values"
				allowedCtyValues := createStringVals(rule.ListPolicy.AllowedValues)
				if len(rule.ListPolicy.AllowedValues) > 0 {
					listPolicyBlock.Body().SetAttributeValue("allowed_values", cty.ListVal(allowedCtyValues))
				}

				listPolicyBlock.Body().SetAttributeValue("inherit_from_parent", cty.BoolVal(rule.ListPolicy.InheritFromParent))
				listPolicyBlock.Body().SetAttributeValue("suggested_value", cty.StringVal(rule.ListPolicy.SuggestedValue))
			}

			// Handle optional Condition
			if rule.Condition != nil {
				conditionBlock := policyRuleBlock.Body().AppendNewBlock("condition", nil)
				conditionBlock.Body().SetAttributeValue("description", cty.StringVal(rule.Condition.Description))
				conditionBlock.Body().SetAttributeValue("expression", cty.StringVal(rule.Condition.Expression))
				conditionBlock.Body().SetAttributeValue("title", cty.StringVal(rule.Condition.Title))
			}

			// Handle optional parameters
			if rule.Parameters != nil {
				parametersBlock := policyRuleBlock.Body().AppendNewBlock("parameters", nil)
				for _, field := range rule.Parameters.Fields {
					fieldBlock := parametersBlock.Body().AppendNewBlock("fields", nil)
					fieldBlock.Body().SetAttributeValue("key", cty.StringVal(field.Key))
					if field.Value != nil {
						valueBlock := fieldBlock.Body().AppendNewBlock("value", nil)
						if field.Value.BoolValue {
							valueBlock.Body().SetAttributeValue("bool_value", cty.BoolVal(field.Value.BoolValue))
						}
						if field.Value.NullValue != "" {
							valueBlock.Body().SetAttributeValue("null_value", cty.StringVal(field.Value.NullValue))
						}
						if field.Value.StringValue != "" {
							valueBlock.Body().SetAttributeValue("string_value", cty.StringVal(field.Value.StringValue))
						}
					}
				}
			}

			// Handle optional resource_types
			if rule.ResourceTypes != nil {
				resourceTypesBlock := policyRuleBlock.Body().AppendNewBlock("resource_types", nil)
				resourceTypesBlock.Body().SetAttributeValue("included", cty.StringVal(rule.ResourceTypes.Included))
			}
		}

	case "customorgpolicy":
		if policy.Constraint.CustomOrgPolicyConstraint == nil {
			return nil, fmt.Errorf("missing CustomOrgPolicyConstraint data for custom org policy %s", metadata.PolicyID)
		}
		customOrgPolicyConstraintBlock := constraintBlock.Body().AppendNewBlock("org_policy_constraint_custom", nil)
		customConstraintBlock := customOrgPolicyConstraintBlock.Body().AppendNewBlock("custom_constraint", nil)
		customConstraintBlock.Body().SetAttributeValue("name", cty.StringVal(policy.Constraint.CustomOrgPolicyConstraint.CustomConstraint.Name))
		customConstraintBlock.Body().SetAttributeValue("display_name", cty.StringVal(policy.Constraint.CustomOrgPolicyConstraint.CustomConstraint.DisplayName))
		customConstraintBlock.Body().SetAttributeValue("description", cty.StringVal(policy.Constraint.CustomOrgPolicyConstraint.CustomConstraint.Description))
		customConstraintBlock.Body().SetAttributeValue("action_type", cty.StringVal(policy.Constraint.CustomOrgPolicyConstraint.CustomConstraint.ActionType))
		customConstraintBlock.Body().SetAttributeValue("condition", cty.StringVal(policy.Constraint.CustomOrgPolicyConstraint.CustomConstraint.Condition))
		customConstraintBlock.Body().SetAttributeValue("method_types", cty.ListVal(createStringVals(policy.Constraint.CustomOrgPolicyConstraint.CustomConstraint.MethodTypes)))
		customConstraintBlock.Body().SetAttributeValue("resource_types", cty.ListVal(createStringVals(policy.Constraint.CustomOrgPolicyConstraint.CustomConstraint.ResourceTypes)))

		// Iterate over PolicyRules
		for _, rule := range policy.Constraint.CustomOrgPolicyConstraint.PolicyRules {
			policyRuleBlock := customOrgPolicyConstraintBlock.Body().AppendNewBlock("policy_rules", nil)
			policyRuleBlock.Body().SetAttributeValue("enforce", cty.BoolVal(rule.Enforce))

			if rule.Condition != nil {
				conditionBlock := policyRuleBlock.Body().AppendNewBlock("condition", nil)
				conditionBlock.Body().SetAttributeValue("description", cty.StringVal(rule.Condition.Description))
				conditionBlock.Body().SetAttributeValue("expression", cty.StringVal(rule.Condition.Expression))
				conditionBlock.Body().SetAttributeValue("title", cty.StringVal(rule.Condition.Title))
			}
		}

	default:
		return nil, fmt.Errorf("unknown policy type: %s", policyType)
	}

	for _, standard := range metadata.ComplianceStandards { // Access ComplianceStandards from metadata
		if standard.Control != "" && standard.Standard != "" {
			complianceStandardsBlock := policyBlock.Body().AppendNewBlock("compliance_standards", nil)
			complianceStandardsBlock.Body().SetAttributeValue("standard", cty.StringVal(standard.Standard))
			complianceStandardsBlock.Body().SetAttributeValue("control", cty.StringVal(standard.Control))
		}
	}

	// Set description, and append the policy to the policySet block
	policyBlock.Body().SetAttributeValue("description", cty.StringVal(metadata.Description)) // Use metadata.Description
	newPolicySet.Body().AppendBlock(policyBlock)

	return newPolicySet, nil
}
