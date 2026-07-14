# Verified Source Log

Verification date: 2026-07-14.

This file records primary or official sources consulted for the SecFlowOps artifact. It does not claim a systematic literature review. Sources listed here may support tool-scope or framework-scope statements, but only peer-reviewed or standards sources should support scientific novelty claims.

| ID | Source | URL | Verified facts used | Status |
|---|---|---|---|---|
| SRC-OPA-DOCS | Open Policy Agent documentation | https://www.openpolicyagent.org/docs | OPA is a general-purpose policy engine; policies are written in Rego; OPA can be used in CI/CD contexts. | confirmed |
| SRC-GHA-DOCS | GitHub Actions documentation | https://docs.github.com/en/actions | GitHub Actions provides workflow automation through YAML workflows triggered by repository events. | confirmed |
| SRC-GH-CODEQL | GitHub code scanning documentation | https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities | GitHub code scanning surfaces code vulnerabilities and supports CodeQL-based analysis. | confirmed |
| SRC-GH-DEPENDABOT | GitHub Dependabot quickstart | https://docs.github.com/en/code-security/tutorials/secure-your-dependencies/dependabot-quickstart | Dependabot supports dependency alerting and update automation. | confirmed |
| SRC-GH-SECRETS | GitHub secret scanning documentation | https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning | GitHub secret scanning detects supported secrets in repositories. | confirmed |
| SRC-SEMGREP-DOCS | Semgrep documentation | https://docs.semgrep.dev/ | Semgrep supports rule-driven static analysis and JSON output. | confirmed |
| SRC-TRIVY-DOCS | Trivy documentation | https://trivy.dev/docs/latest/guide/ | Trivy supports filesystem targets and vulnerability, secret, and misconfiguration scanning categories. | confirmed |
| SRC-GITLEAKS | Gitleaks repository | https://github.com/gitleaks/gitleaks | Gitleaks is a repository secret detection tool. | confirmed |
| SRC-ZAP-DOCS | OWASP ZAP documentation | https://www.zaproxy.org/docs/ | OWASP ZAP is the DAST tool used for web application scanning; local ZAP 2.17.0 execution is recorded in the ZAP probe report. | confirmed |
| SRC-OPENSFF-SCORECARD | OpenSSF Scorecard | https://scorecard.dev/ | OpenSSF Scorecard evaluates open-source project supply-chain security practices. | confirmed |
| SRC-NIST-204D | NIST SP 800-204D | https://csrc.nist.gov/pubs/sp/800/204/d/final | NIST SP 800-204D covers integration of software supply-chain security in DevSecOps CI/CD pipelines. | confirmed |
| SRC-NIST-SSDF | NIST SP 800-218 | https://doi.org/10.6028/NIST.SP.800-218 | NIST SP 800-218 defines SSDF Version 1.1 recommendations for mitigating software vulnerability risk. | confirmed |
| SRC-OWASP-SAMM | OWASP SAMM | https://owasp.org/www-project-samm/ | OWASP SAMM provides a software assurance maturity model across software lifecycle activities. | confirmed |
| SRC-MYRBAKKEN-DEVSECOPS | DevSecOps: A Multivocal Literature Review | https://doi.org/10.1007/978-3-319-67383-7_2 | DevSecOps literature frames security as integrated with development and operations practices. | confirmed via Crossref |
| SRC-JOHNSON-SAST | Why don't software developers use static analysis tools to find bugs? | https://doi.org/10.1109/ICSE.2013.6606613 | Developer adoption and warning-management issues limit scanner-only value. | confirmed via Crossref |
| SRC-BELLER-SAST | Analyzing the State of Static Analysis: A Large-Scale Evaluation in Open Source Software | https://doi.org/10.1109/SANER.2016.105 | Static-analysis value depends on project context, adoption, and warning interpretation. | confirmed via Crossref |
| SRC-PARIZI-BENCHMARK | Benchmark Requirements for Assessing Software Security Vulnerability Testing Tools | https://doi.org/10.1109/COMPSAC.2018.00139 | Security-tool evaluation requires explicit targets, measurements, and comparability criteria. | confirmed via Crossref |
| SRC-DECAN-NPM | On the impact of security vulnerabilities in the npm package dependency network | https://doi.org/10.1145/3196398.3196401 | npm vulnerability exposure must be interpreted through dependency-network behavior. | confirmed via Crossref |
| SRC-MIRHOSSEINI-PR | Can automated pull requests encourage software developers to upgrade out-of-date dependencies? | https://doi.org/10.1109/ASE.2017.8115621 | Automated dependency-update pull requests require evaluation of acceptance, failures, and residual risk. | confirmed via Crossref |

## Non-Verified or Not Used for Central Claims

Semantic Scholar API searches were not executed because no API key was provided in the workspace. Crossref was used to verify the peer-reviewed references added to the paper bibliography. No unverified paper is used to support a central claim in the current paper.
