############## THIS FILE IS MANAGED BY REPOSITORY AUTOMATION ##############

# THIS RESOURCE CANNOT DEPLOY POSTURES CONTAINING REGO POLICIES AT THE MOMENT
#
# PLEASE REFRAIN FROM MAKING MANUAL EDITS TO THIS REPOSITORY
# EXCEPT IN CASES OUTLINED BELOW:

/** 
* This Terraform file is responsible for creating the "tfc_test_posture" security posture
* and deploying it to "organizations/629636424835" with a posture deployment resource.
* 
* Please do not edit the "google_securityposture_posture" resource. It may be necessary, however, upon
* initial setup to import any existing posture resources and posture deployment resources as such:
* 
* import {
*   id = "{{parent}}/locations/{{location}}/postures/{{posture_id}}"
*   to = google_securityposture_posture.default
* }
* 
*/

####################### POSTURE DEPLOYMENT SECTION: #######################


# Create a new posture deployment ID each time we update the posture
resource "random_id" "asgdjskalgfs" {
  keepers = {
    # Generate a new id each time we update the posture
    posture_revision_id = google_securityposture_posture.tfc_test_posture.revision_id
  }
  byte_length = 4
}

# Create the posture deployment
resource "google_securityposture_posture_deployment" "tfc_test_posture_deployment" {
  location              = "global"
  parent                = "organizations/629636424835"
  posture_deployment_id = "deployment-${google_securityposture_posture.tfc_test_posture.revision_id}-${random_id.asgdjskalgfs.hex}"
  posture_id            = google_securityposture_posture.tfc_test_posture.id
  posture_revision_id   = google_securityposture_posture.tfc_test_posture.revision_id
  target_resource       = "organizations/629636424835"

  depends_on = [google_securityposture_posture.tfc_test_posture]
}

resource "google_securityposture_posture" "tfc_test_posture" {
  posture_id  = "tfc-test-posture"
  parent      = "organizations/629636424835" # e.g., organizations/123, folders/456, projects/789
  location    = "global"
  state       = "ACTIVE" # Or "DEPRECATED"
  description = "Test posture for testing TFC connection with VCS repo."

  policy_sets {
    policy_set_id = "customsha_policy_set"
    description   = "::DO NOT EDIT::Policy Set for only customsha policies, auto-inlined from repository."
    policies {
      policy_id = "artifactRegistryScanningApiEnabled"
      constraint {
        security_health_analytics_custom_module {
          config {
            predicate {
              expression = "!(resource.name.contains('containerscanning.googleapis.com'))"
            }
            resource_selector {
              resource_types = ["serviceusage.googleapis.com/Service"]
            }
            description    = "When enforced, this detector finds if the container scanning API is enabled for projects that have an Artifact Registry repository."
            severity       = "MEDIUM"
            recommendation = "Enable containerscanning.googleapis.com"
          }
          module_enablement_state = "ENABLED"
          display_name            = "artifactRegistryScanningApiEnabled"
        }
      }
      compliance_standards {
        standard = "Example Standards"
        control  = "ABC-123"
      }
      description = "Require artifact registry scanning API to be enabled."
    }
  }
  policy_sets {
    policy_set_id = "orgpolicy_policy_set"
    description   = "::DO NOT EDIT::Policy Set for only orgpolicy policies, auto-inlined from repository."
    policies {
      policy_id = "computeInstanceVMExternalIpAccess"
      constraint {
        org_policy_constraint {
          canned_constraint_id = "compute.vmExternalIpAccess"
          policy_rules {
            deny_all = true
          }
        }
      }
      compliance_standards {
        standard = "Example Standards"
        control  = "DEF-234"
      }
      compliance_standards {
        standard = "Example Standards"
        control  = "GHI-345"
      }
      description = "Deny external access for GCE instances."
    }
  }
  policy_sets {
    policy_set_id = "sha_policy_set"
    description   = "::DO NOT EDIT::Policy Set for only sha policies, auto-inlined from repository."
    policies {
      policy_id = "APIKeyExists"
      constraint {
        security_health_analytics_module {
          module_name             = "API_KEY_EXISTS"
          module_enablement_state = "ENABLED"
        }
      }
      compliance_standards {
        standard = "Organization Custom Standards"
        control  = "4.3"
      }
      compliance_standards {
        standard = "NIST SP 800-53"
        control  = "SC-13"
      }
      description = "SHA Module API_KEY_EXISTS"
    }
  }
}

# Terraform documentation:
# https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/securityposture_posture
