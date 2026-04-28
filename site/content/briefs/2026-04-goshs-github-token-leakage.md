---
title: goshs GitHub Token Leakage via ArtiPACKED Vulnerability (CVE-2026-40903)
slug: 2026-04-goshs-github-token-leakage
description: The goshs SimpleHTTPServer prior to version 2.0.0-beta.6 is vulnerable to ArtiPACKED, potentially leading to leakage of the GITHUB_TOKEN through workflow artifacts.
date: "2026-04-22T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-40903
  - github_token
  - credential-access
  - artipacked
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-40903
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40903
  - https://github.com/patrickhener/goshs/security/advisories/GHSA-hpxj-9fgp-fhhf
rules:
  - title: Detect goshs Process Execution
    description: Detects execution of goshs, which might indicate use of the vulnerable SimpleHTTPServer.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Network Connection from goshs
    description: Detects outbound network connection from goshs process.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The goshs SimpleHTTPServer, written in Go, is susceptible to an ArtiPACKED vulnerability (CVE-2026-40903) in versions prior to 2.0.0-beta.6. This vulnerability can lead to the unintended leakage of the `GITHUB_TOKEN` through workflow artifacts. Even if the token is not directly present in the repository's source code, the ArtiPACKED issue allows for its exposure during workflow execution. This is a significant risk for projects using goshs in their CI/CD pipelines, as a compromised `GITHUB_TOKEN` can grant attackers unauthorized access to the repository and its associated resources. Organizations utilizing goshs should upgrade to version 2.0.0-beta.6 or later to mitigate this vulnerability. The vulnerability was reported and patched in April 2026.

## Attack Chain

1. A developer introduces a vulnerable version of goshs (prior to 2.0.0-beta.6) into a project's dependencies.
2. The project utilizes GitHub Actions or a similar CI/CD system.
3. The CI/CD workflow is configured to use or interact with the `GITHUB_TOKEN`.
4. Due to the ArtiPACKED vulnerability, the `GITHUB_TOKEN` becomes exposed within the workflow's generated artifacts.
5. An attacker gains access to these workflow artifacts, potentially through misconfigured permissions or compromised systems.
6. The attacker extracts the leaked `GITHUB_TOKEN` from the artifacts.
7. The attacker uses the compromised `GITHUB_TOKEN` to authenticate to the GitHub repository.
8. With the compromised token, the attacker can perform actions such as code modification, secret retrieval, or infrastructure changes depending on the token's permissions.

## Impact

Successful exploitation of CVE-2026-40903 can lead to the leakage of sensitive `GITHUB_TOKEN` credentials, potentially granting unauthorized access to the affected GitHub repository. The impact of this vulnerability could include code tampering, unauthorized access to secrets, and potential compromise of associated infrastructure. The CVSS v3.1 score of 9.1 highlights the critical nature of this vulnerability. The number of affected organizations depends on the adoption rate of vulnerable goshs versions.

## Recommendation

*   Upgrade goshs to version 2.0.0-beta.6 or later to remediate the ArtiPACKED vulnerability as detailed in CVE-2026-40903.
*   Review and restrict the permissions granted to the `GITHUB_TOKEN` in GitHub Actions workflows to minimize potential impact if the token is compromised.
*   Implement artifact scanning tools to detect potential secrets leakage in CI/CD workflow artifacts.
*   Monitor GitHub audit logs for suspicious activity originating from the `GITHUB_TOKEN`, particularly after the introduction or update of goshs.
