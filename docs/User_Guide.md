# User Guide

## 1. Environment Setup

The following setup is required for any new policy engineer working with the
Adaptive Governance Framework. First, ensure you have the following set up:

* Security Command Center (Premium or Enterprise). This is because AGF at the
    moment interacts with the SCC Security Posture service, and it's meant to
    directly generate the Terraform resources you will use in your
    Infrastructure pipelines.
* **pre-commit (optional):** For managing and running Git hooks automatically
    before commits.

Pre-commit is an optional tool, but it will help speed up your developer
workflows by providing you with essentially the same validations that are
performed by [Github Actions workflows](Github_Actions.md) in the repository.
Please visit their [website](https://pre-commit.com/) to learn more.

Once installed, `pre-commit install` sets up the Git hooks defined in
`.pre-commit-config.yaml`. This command only needs to be run once per clone.

* **How it Works:** When you run `git commit`, the hooks defined in
    `.pre-commit-config.yaml` will execute automatically on the staged files.
    These include:
  * Standard checks (YAML, JSON, TOML formatting, trailing whitespace,
        etc.).
  * Go checks (`go mod tidy`, `go test`).
  * **AGF CLI checks:** Hooks like `agf-lint-all`, `agf-validate-terraform`,
        `agf-validate-policies`.
* **AGF Version Management:** The AGF-specific hooks use a helper script
    (`./scripts/run-agf.sh`) which automatically downloads and caches the
    specific version of `agf` defined in the `.pre-commit-config.yaml`. **You do
    not need to have `agf` installed locally just for the pre-commit hooks to
    work.** However, the Go hooks (`go-mod-tidy`, `go-unit-tests`) do require a
    local Go installation.
* **Failures:** If any hook fails, the commit will be aborted. Review the
    error message, fix the issues (some hooks like formatters might fix things
    automatically), `git add` the changes again, and re-run `git commit`.

### Installing the `agf` CLI

While the pre-commit hooks automatically download and use a specific version of
`agf` (see Section 5), you will likely want to install `agf` locally for manual
testing, debugging, or running commands outside the pre-commit process.

Choose one of the following methods:

* **Method A: Using `go install` (Recommended if Go is installed)** This
    compiles and installs the latest version from the main branch directly from
    GitHub.

    ```bash
    # Replace with the correct repository path
    go install [github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@latest](https://github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@latest)
    # Or install a specific version
    # go install [github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@v0.2.0](https://github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@v0.2.0)
    ```

    *Ensure your Go bin directory (`$GOPATH/bin` or `$HOME/go/bin`) is in your
    system's `PATH`.*

* **Method B: Downloading from GitHub Releases**

    1. Go to the repository's
        [Releases page](https://github.com/YOUR_USERNAME/YOUR_REPO/releases).
    2. Download the appropriate archive (`.tar.gz` or `.zip`) for your
        OS/architecture from the desired release version.
    3. Extract the `agf` (or `agf.exe`) binary.
    4. Move the binary to a directory in your system's `PATH` (e.g.,
        `/usr/local/bin`, `~/bin`, `C:\tools`).
    5. On Linux/macOS, make it executable: `chmod +x /path/to/agf`.

## 2. Creating a new Posture

If you need to create a new Terraform or YAML posture, you can use AGF to create
a new posture resource:

```bash
agf new-posture \
  --name="sample_posture" \             # Name (letters, numbers, and underscores, please!)
  --description="A sample description"  # A descriptive description
  --parent="organizations/123456789"    # The organization this posture will be deployed under (not "TO")
  --target="folders/112358132134"       # The hierarchy node this posture will be deployed to (project, folder, organization)
```

This creates a new "posture_name.tf" resource in your build/postures directory,
and sets it up to be ready to receive new policies you author and manage.

All of these inputs (except "description") are required. Be sure your posture
name is snake_case and does not include numbers. This script will create new
Terraform and YAML posture files in the "build/" directory.

## 3. Authoring Policies

Now that you have your local developer environment set up, we can begin writing
policies! In general, each policy will contain:

1. A definition of that policy, and
2. Metadata about that policy.

There are also five different kinds of policies that you can incorporate into a
security posture:

* Org policies
* Custom org policies
* SHA modules
* Custom SHA modules

We consider the GCP-native policy types (Org policies and SHA modules) as
**"detectors"** in this repository.

The *"files"* highlighted here include the policy or detector's definition and
metadata about the policy or detector.

### Creating a new policy

To create a new policy, you will need to define a `metadata.yaml` file and a
`policy.yaml` file.

#### Metadata

All policies require a `metadata.yaml` file in their folder. Here's a syntax
rundown for this metadata file:

```yaml
author: Author's email address (ie. tdesrosi@example.com)
policyId: Policy ID as defined by the design document (ie. RestrictAWSBucketLocation)
description: A description of what this policy does (ie. Location of AWS S3 Bucket cannot be us-east-1.)

### This is a list of security postures this policy should be added to. In this example,
### "folder_a_posture" is a reference to the file "build/postures/folder_a_posture.tf"
postures:
  - folder_a_posture

### This is an OPTIONAL list of compliance standards this policy maps to. These do not need to
### be industry-standard or public compliance standards. They could reference Scotiabank operational
### requirements and tie back to a section of a Confluence page, for instance.
complianceStandards:
  - standard: "SB-111"
    control: "2.3"
  - standard: "NIST 800-53"
    control: "AC-5"
```

#### Policy Definitions

As a reminder, policies are in reference to the policies authored in the
`detectors/` directory. These include org policies, custom org policies, SHA
modules, and custom SHA modules. In this repository, we define these policies in
YAML files in their respective policy folders. The schema of these files follows
the
[API documentation](https://cloud.google.com/security-command-center/docs/reference/securityposture/rest/v1/organizations.locations.postures#resource:-posture)
**exactly**.

We use the
[constraint](https://cloud.google.com/security-command-center/docs/reference/securityposture/rest/v1/PolicySet#constraint)
object to define each policy. **The first-level key is always `constraint:`**.
Here's an example for each policy type:

#### Org Policy Constraint

```yaml
constraint:
  orgPolicyConstraint:
    cannedConstraintId: compute.vmExternalIpAccess
    policyRules:
    - denyAll: true
```

#### Custom Org Policy Constraint

```yaml
constraint:
  orgPolicyConstraintCustom:
    customConstraint:
      name: organizations/123456789/customConstraints/custom.cryptoKeyRotationPeriod
      displayName: "CryptoKey Rotation Period Maximum 90 days"
      description: "This policy enforces that all secrets be configured with a rotation period
        less than or equal to 90 days on creation or update."
      actionType: ALLOW
      condition: "resource.rotationPeriod <= duration('90d')"
      methodTypes:
        - CREATE
        - UPDATE
      resourceTypes:
        - cloudkms.googleapis.com/CryptoKey
    policyRules:
      - enforce: true
```

#### SHA Module

```yaml
constraint:
  securityHealthAnalyticsModule:
    moduleName: API_KEY_EXISTS
    moduleEnablementState: ENABLED
```

#### Custom SHA Module

```yaml
constraint:
  securityHealthAnalyticsCustomModule:
    config:
      customOutput: {}
      description: When enforced, this detector finds if the container scanning API is
        enabled for projects that have an Artifact Registry repository.
      predicate:
        expression: "!(resource.name.contains('containerscanning.googleapis.com'))"
      resourceSelector:
        resourceTypes:
        - serviceusage.googleapis.com/Service
      severity: MEDIUM
      recommendation: "Enable containerscanning.googleapis.com"
    displayName: artifactRegistryScanningApiEnabled
    moduleEnablementState: ENABLED
```

Please keep in mind that the schema for these detector policies comes directly
from the API documentation. If you are ever in doubt, please reference the
documentation.
