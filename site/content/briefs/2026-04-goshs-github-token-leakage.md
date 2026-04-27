---
title: goshs GitHub Token Leakage via ArtiPACKED Vulnerability (CVE-2026-40903)
slug: 2026-04-goshs-github-token-leakage
description: The goshs SimpleHTTPServer prior to version 2.0.0-beta.6 is vulnerable to ArtiPACKED, potentially leading to leakage of the GITHUB_TOKEN through workflow artifacts.
date: "2026-04-22T12:00:00Z"
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

The goshs SimpleHTTPServer, written in Go, is susceptible to an ArtiPACKED vulnerability (CVE-2026-40903) in versions prior to 2.0.0-beta.6. This vulnerability can lead to the unintended leakage of the `GITHUB_TOKEN` through workflow artifacts. Even if the token is not directly present in the repository's source code, the ArtiPACKED issue allows for its exposure during workflow execution. This is a significant risk for projects using goshs in their CI/CD pipelines, as a compromised…
