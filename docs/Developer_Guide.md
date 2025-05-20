# AGF Project Developer Guide

Welcome to the AGF project! This guide provides instructions for setting up your development environment, contributing
code, and understanding our workflows.

## 1. Project Overview

AGF is a Command Line Interface (CLI) tool designed for repository maintenance, validation of configuration files (like
Terraform security postures and detector policies), and other automated tasks within this repository.

This repository contains both the Go source code for the `agf` CLI itself and the policy/configuration files it manages.

## 2. Prerequisites

Before you begin, ensure you have the following installed:

* **Go:** Version 1.23 or higher (check `go.mod` for the exact version). Needed for running tests, building `agf`
  locally if desired, and for some pre-commit hooks.
* **pre-commit:** For managing and running Git hooks automatically before commits. Install it via pip:

Pre-commit is an optional tool, but it will help speed up your developer workflows by providing you with essentially the
same validations that are performed by [Github Actions workflows](Github_Actions.md) in the repository.

**Install Pre-commit Hooks:** Set up the Git hooks defined in `.pre-commit-config.yaml`. This command only needs to
   be run once per clone.

    ```bash
    pre-commit install
    ```

## 3. Installing the `agf` CLI Locally (Optional, but Recommended)

While the pre-commit hooks automatically download and use a specific version of `agf` (see Section 5), you will likely
want to install `agf` locally for manual testing, debugging, or running commands outside the pre-commit process.

Choose one of the following methods:

* **Method A: Using `go install` (Recommended if Go is installed)**
    This compiles and installs the latest version from the main branch directly from GitHub.

    ```bash
    # Replace with the correct repository path
    go install [github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@latest](https://github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@latest)
    # Or install a specific version
    # go install [github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@v0.2.0](https://github.com/YOUR_USERNAME/YOUR_REPO/cmd/agf@v0.2.0)
    ```

    *Ensure your Go bin directory (`$GOPATH/bin` or `$HOME/go/bin`) is in your system's `PATH`.*

* **Method B: Downloading from GitHub Releases**
    1. Go to the repository's [Releases page](https://github.com/YOUR_USERNAME/YOUR_REPO/releases).
    2. Download the appropriate archive (`.tar.gz` or `.zip`) for your OS/architecture from the desired release version.
    3. Extract the `agf` (or `agf.exe`) binary.
    4. Move the binary to a directory in your system's `PATH` (e.g., `/usr/local/bin`, `~/bin`, `C:\tools`).
    5. On Linux/macOS, make it executable: `chmod +x /path/to/agf`.

## 4. Pre-Commit Hooks

We use `pre-commit` to automatically run checks before each commit. This helps maintain code quality and consistency.

* **Setup:** You already ran `pre-commit install` in the Getting Started section.
* **How it Works:** When you run `git commit`, the hooks defined in `.pre-commit-config.yaml` will execute automatically
  on the staged files. These include:
  * Standard checks (YAML, JSON, TOML formatting, trailing whitespace, etc.).
  * Go checks (`go mod tidy`, `go test`).
  * **AGF CLI checks:** Hooks like `agf-lint-all`, `agf-validate-terraform`, `agf-validate-policies`.
* **AGF Version Management:** The AGF-specific hooks use a helper script (`./scripts/run-agf.sh`) which automatically
  downloads and caches the specific version of `agf` defined in the `.pre-commit-config.yaml`. **You do not need to have
  `agf` installed locally just for the pre-commit hooks to work.** However, the Go hooks (`go-mod-tidy`,
  `go-unit-tests`) do require a local Go installation.
* **Failures:** If any hook fails, the commit will be aborted. Review the error message, fix the issues (some hooks like
  formatters might fix things automatically), `git add` the changes again, and re-run `git commit`.

## 6. Development Workflow

1. **Create a Branch:** Always work on a feature or bugfix branch, branching off `main`.

    ```bash
    git checkout main
    git pull origin main
    git checkout -b your-feature-branch-name
    ```

2. **Make Changes:** Edit the necessary code (Go source, Rego policies, Terraform files, etc.).
3. **Run Tests Locally (Optional but Recommended):**

    ```bash
    # Run Go unit tests for the whole module
    go test ./...
    # Run specific agf commands if needed
    # agf lint --all
    # agf validate --terraform
    ```

4. **Stage Changes:**

    ```bash
    git add <files you changed>
    ```

5. **Commit Changes:**

    ```bash
    git commit -m "Your descriptive commit message"
    ```

    * Please review our requirements for commit messages below. The pre-commit hooks will run automatically. Fix any
      issues reported.
6. **Push Branch:**

    ```bash
    git push origin your-feature-branch-name
    ```

7. **Create Pull Request:** Open a Pull Request (PR) on GitHub from your branch to `main`.
8. **CI Checks:** GitHub Actions workflows will run automatically on your PR (e.g., unit tests, coverage checks, build
   validation). Ensure these pass.
9. **Review and Merge:** Once reviewed and approved, the PR can be merged into `main`.

## 7. Commit Messages

Please write clear and descriptive commit messages. While not strictly enforced *yet* (TODO), following a convention
helps with understanding history and automated changelog generation. Consider using prefixes like:

* `feat:` for new features.
* `fix:` for bug fixes.
* `docs:` for documentation changes.
* `style:` for formatting changes.
* `refactor:` for code changes that neither fix a bug nor add a feature.
* `perf:` for performance improvements.
* `test:` for adding or improving tests.
* `build:` for changes affecting the build system or dependencies.
* `ci:` for changes to CI configuration.
* `chore:` for routine tasks or maintenance.

Meaningful messages greatly improve the quality of the release notes generated by GoReleaser.

## 8. Release Process (Maintainers Only)

Releases are created using a combination of manual triggering and automation via GitHub Actions and GoReleaser.

1. **Triggering:** A maintainer initiates a release via the GitHub Actions UI:
    * Go to the "Actions" tab.
    * Select the "Release CLI" workflow.
    * Click "Run workflow".
    * Input the required version number (e.g., `1.2.3`, *without* the `v` prefix).
    * Ensure the target branch is correct (usually `main`).
    * Click "Run workflow".
2. **Automation:** The triggered workflow will:
    * Checkout the specified branch.
    * Create and push the corresponding Git tag (e.g., `v1.2.3`).
    * Run the `goreleaser/goreleaser-action`.
3. **GoReleaser:** GoReleaser then takes over:
    * Builds the `agf` binary for multiple platforms (Linux, macOS, Windows; amd64, arm64).
    * Creates archives (`.tar.gz`, `.zip`) and checksums.
    * Generates release notes based on commit history since the last tag.
    * Creates (or updates) a GitHub Release for the tag.
    * Uploads the binaries, checksums, and release notes as assets to the GitHub Release.

*Note: Releases can also be triggered by manually pushing a tag matching `v*` directly to the repository, but the
recommended method for maintainers is via the `workflow_dispatch` UI trigger.*

## 9. Code Coverage

Code coverage is automatically checked on Pull Requests and pushes to `main` via the `coverage-badge.yml` workflow. This
workflow:

1. Runs Go unit tests and generates a coverage profile (`coverage.out`).
2. On pushes to `main`, it uses the `ncruces/go-coverage-report` action to calculate the coverage percentage.
3. It generates an SVG coverage badge and a detailed HTML report.
4. These artifacts are automatically committed and pushed to the repository's Wiki.
5. The coverage badge displayed in the `README.md` is automatically updated.

---

Thank you for contributing! Please reach out if you have any questions.
