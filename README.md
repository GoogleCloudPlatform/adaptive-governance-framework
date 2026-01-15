# Adaptive Governance Framework

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/GoogleCloudPlatform/adaptive-governance-framework.git)

> [!NOTE]
> This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software
> Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

## Introduction

Large enterprises, especially those in regulated industries, face lengthy timelines to begin using GCP due in large part
to their security and compliance requirements. They often have well-established cybersecurity organizations and mappings
of critical control requirements that must be met before they can use our products and services. Before moving to GCP,
they also may have experience implementing declarative governance controls through other platforms, such as [Terraform
Sentinel](https://developer.hashicorp.com/sentinel/docs/terraform), [Styra](https://www.styra.com/), and
[OPA](https://www.openpolicyagent.org/) frameworks like
[Gatekeeper](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/).

Organizations are looking for a unified plane of glass with which to define controls:

* That notify the proper teams when security misconfigurations are detected,
* That can be implemented in IaC pipelines as guardrails for developers, and
* Whose implementation details can be easily communicated to stakeholders.

**Adaptive Governance Framework (AGF)** Is an attempt at codifying the policy authoring, management, and organization
process for policy engineering teams working with Security Command Center (primarily). AGF is a repository consisting
of tooling and a policy library structure that allow for security and compliance requirements to be defined:

* In one place (a global source-of-truth policy repository),
* As-code (through Terraform resources), and
* With formatting, validation, and unit and integration testing built-in.

The resulting Terraform resources are deployed declaratively using the Security Posture Service in
[Security Command Center](https://cloud.google.com/security-command-center/docs/security-posture-overview) (SCC).

![Development Methodology](docs/img/define-once-deploy-many.png)

**We want to decouple policy authoring from posture deployment.** *Why?*

Declarative policy management is awesome, but it's only awesome if our developers aren't pulling their hair out. No
matter the tool you use (Whether SCC Postures deployed from Terraform resources, Wiz GraphQL queries, and the like),
every policy engineer comes to the same conclusion: We always have to manage large files, and have no way of testing or
validating them before we try and deploy them (and receive an error from the CSP an hour into the process).

AGF is positioned to help policy engineers save time and streamline the policy development process. Put another way: We
use our Policy as Code to help control and streamline the Infrastructure as Code process, why not do the same for the
Policy as Code process. It's virtually the **same thing**:

![It's all Infrastructure as Code](docs/img/its-all-iac.png)

## Design

Policies are developed away from the *google_securityposture_posture* Terraform resource in order
to avoid confusion and human error, as the file is quite large. Each subdirectory contains definitions, code, and
configuration parameters for each policy type (SHA and OPC for now, but support for new policy types is on the way as
new features are introduced). Policies are defined in the `detectors/` folder, which is where policy engineers will
spend most of their time.

A Golang CLI tool (AGF CLI, built with [Cobra](https://github.com/spf13/cobra)) is the frontend for repository
management. It will:

* Validate the structure of policies against REST API requirements,
* Build and maintain Terraform security postures for you, so you only need to worry about your policies,
* Help you set up and define new security posture targets,
* and much more... (Read up on [Repository Design](docs/Repository_Design.md) for more)

## Getting Started

1. Clone the repository.
2. Take a look at the sample policies and the resulting security postures for inspiration.
3. Connect the `build/postures` folder to your IaC workflow (This is the output directory for security posture
   resources).
4. Have fun! For more detailed information, check out the [User Guide](docs/User_Guide.md).

## Further Reading

More in-depth information is compiled in the `docs/` directory:

* [Developer_Guide](docs/Developer_Guide.md)
* [Github Actions](docs/Github_Actions.md)
* [Repository Design](docs/Repository_Design.md)
* [User Guide](docs/User_Guide.md)

## Contributing

Please follow the guidance in the [Contribution guide](./CONTRIBUTING.md).
