# GitHub Governance Probe

This file exists only to exercise the protected-branch governance path after enabling CODEOWNERS and branch protection on `main`.

Expected GitHub behavior for the pull request that adds this file:

- the `validate-artifact` CI check must pass;
- the branch must be up to date with `main`;
- two approving reviews are required;
- code-owner review is required;
- self-approval by the PR author is refused by GitHub;
- merge is blocked until the protection requirements are satisfied.

The exported API evidence for this probe is stored under `SecFlowOps/experiments/github_governance_evidence/`.