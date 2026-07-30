---
title: Authorization Bypass Vulnerability in IBM Langflow OSS
slug: 2026-07-langflow-auth-bypass
description: IBM Langflow OSS versions 1.0.0 through 1.10.1 contain an authorization bypass vulnerability (CVE-2026-12945) allowing authenticated users to access and manipulate build jobs of other users.
date: "2026-07-30T17:30:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-12945
  - authorization-bypass
  - cwe-639
vendors:
  - IBM
products:
  - Langflow OSS (1.10.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM Langflow OSS 1.0.0 through 1.10.1 allows authenticated users to access and manipulate other users' build jobs through improper access control.
    confidence_band: high
cves:
  - id: CVE-2026-12945
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12945
  - https://www.ibm.com/support/pages/node/7279994
---

IBM Langflow OSS versions 1.0.0 through 1.10.1 are susceptible to an authorization bypass vulnerability identified as CVE-2026-12945. The vulnerability, categorized as CWE-639 (Authorization Bypass Through User-Controlled Key), stems from improper access controls within the application's log retrieval functionality and its build job management endpoints. An attacker with standard authenticated access can manipulate object identifiers to interact with build jobs that they are not authorized to view or modify. This flaw enables unauthorized access to sensitive build logs and potential disruption of build processes, impacting the integrity and confidentiality of the development workflow within environments utilizing the affected versions of Langflow OSS.

## Attack Chain

1. The attacker authenticates to the target IBM Langflow OSS instance with a low-privileged user account.
2. The attacker identifies the application's API endpoints responsible for log retrieval and build job management.
3. The attacker observes that requests to these endpoints include identifiers (e.g., job IDs or user IDs) that can be manipulated.
4. The attacker crafts a malicious HTTP request to the build job endpoint, replacing legitimate identifiers with target identifiers corresponding to other users' jobs.
5. The server fails to validate whether the current authenticated user has sufficient permissions to access the specified resource.
6. The application processes the request and returns the sensitive logs or executes unauthorized actions (manipulation) on the target build job.
7. The attacker repeats this process for multiple job IDs to exfiltrate logs or disrupt build pipelines.

## Impact

Successful exploitation of this vulnerability permits unauthorized access to build logs and the ability to manipulate build jobs belonging to other users. In a CI/CD environment, this can lead to the exposure of proprietary code, environment variables, credentials present in build logs, or the intentional corruption of software build pipelines, resulting in potential service disruption or supply chain compromise.

## Recommendation

1. Upgrade IBM Langflow OSS to a patched version beyond 1.10.1 immediately to remediate CVE-2026-12945.
2. Deploy web application firewall (WAF) or API gateway rules to inspect requests to build endpoints for unauthorized identifier modification (insecure direct object reference patterns).
3. Review access logs for high-frequency or anomalous requests to build management and log retrieval API endpoints originating from standard user accounts.
4. Implement strict role-based access control (RBAC) policies and ensure that all server-side endpoints enforce ownership validation for requested resources.
