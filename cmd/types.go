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

// Policy represents the generic structure for all policy types.
// For up-to-date information about the schema for any of these policies,
// please consult with the documentation available at
// https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/securityposture_posture
type Policy struct {
	PolicyID     string      `yaml:"policy_id"`
	MetadataName string      `yaml:"-"` // Ignore during YAML parsing
	Constraint   *Constraint `yaml:"constraint"`
}

// Constraint represents the different types of constraints.
type Constraint struct {
	SHAModule                 *SHAModule                 `yaml:"securityHealthAnalyticsModule,omitempty"`
	CustomSHAModule           *CustomSHAModule           `yaml:"securityHealthAnalyticsCustomModule,omitempty"`
	OrgPolicyConstraint       *OrgPolicyConstraint       `yaml:"orgPolicyConstraint,omitempty"`
	CustomOrgPolicyConstraint *CustomOrgPolicyConstraint `yaml:"orgPolicyConstraintCustom,omitempty"`
}

// SHAModule represents the structure of a SHA module.
type SHAModule struct {
	ModuleName            string `yaml:"moduleName"`
	ModuleEnablementState string `yaml:"moduleEnablementState"`
}

// CustomSHAModule represents the structure of a custom SHA module.
type CustomSHAModule struct {
	DisplayName string `yaml:"displayName"`
	Config      struct {
		Predicate struct {
			Expression string `yaml:"expression"`
		} `yaml:"predicate"`
		// Corrected (Matches API doc)
		CustomOutput *struct {
			Properties []struct { // <-- Slice of structs
				Name            string `yaml:"name"`
				ValueExpression struct {
					Expression string `yaml:"expression"`
				} `yaml:"valueExpression"`
			} `yaml:"properties"` // Note: YAML tag remains the same
		} `yaml:"customOutput,omitempty"`
		ResourceSelector *struct {
			ResourceTypes []string `yaml:"resourceTypes"`
		} `yaml:"resourceSelector"`
		Severity       string `yaml:"severity"`
		Description    string `yaml:"description"`
		Recommendation string `yaml:"recommendation,omitempty"`
	} `yaml:"config"`
	ModuleEnablementState string `yaml:"moduleEnablementState"`
}

// OrgPolicyConstraint represents the structure of an org policy constraint.
type OrgPolicyConstraint struct {
	CannedConstraintID string `yaml:"cannedConstraintId"`
	PolicyRules        []struct {
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
	} `yaml:"policyRules"`
}

// CustomOrgPolicyConstraint represents the structure of a custom org policy constraint.
type CustomOrgPolicyConstraint struct {
	CustomConstraint struct {
		Name          string   `yaml:"name"`
		DisplayName   string   `yaml:"displayName"`
		Description   string   `yaml:"description"`
		ActionType    string   `yaml:"actionType"`
		Condition     string   `yaml:"condition"`
		MethodTypes   []string `yaml:"methodTypes"`
		ResourceTypes []string `yaml:"resourceTypes"`
	} `yaml:"customConstraint"`
	PolicyRules []struct { // PolicyRules is now a slice of structs
		Enforce   bool `yaml:"enforce"`
		Condition *struct {
			Description string `yaml:"description"`
			Expression  string `yaml:"expression"`
			Title       string `yaml:"title"`
		} `yaml:"condition,omitempty"`
	} `yaml:"policyRules"`
}

// Metadata represents the policy metadata extracted from a YAML file.
// This is type-agnostic (works for any detector policy type)
type Metadata struct {
	PolicyID            string   `yaml:"policyId"`
	PolicyFileName      string   `yaml:"-"`
	Description         string   `yaml:"description"`
	Postures            []string `yaml:"postures"`
	Location            string   `yaml:"location"`
	Author              string   `yaml:"author"`
	PolicyType          string   `yaml:"policyType"`
	Implements          string   `yaml:"implements"`
	ComplianceStandards []struct {
		Standard string `yaml:"standard"`
		Control  string `yaml:"control"`
	} `yaml:"complianceStandards"`
}