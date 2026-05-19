---
title: Coder Azure Instance Identity PKCS#7 Signature Bypass Leads to Unauthenticated Agent Token Theft (CVE-2026-46354)
slug: 2026-05-coder-azure-bypass
description: Coder is vulnerable to a PKCS#7 signature bypass in Azure instance identity (CVE-2026-46354), allowing unauthenticated agent token theft via a forged vmId, enabling access to Git SSH private keys, OAuth access tokens, and workspace secrets.
date: "2026-05-19T20:05:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - pkcs7
  - azure
  - instance identity
  - signature bypass
  - unauthenticated access
  - credential theft
  - cve-2026-46354
  - coder
vendors:
  - Coder
  - Microsoft
  - GitHub
  - GitLab
  - Bitbucket
products:
  - Coder v2
  - azure-instance-identity
  - github.com
  - gitlab.com
  - Bitbucket Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-6x44-w3xg-hqqf
  - https://github.com/coder/coder/pull/25286
  - https://github.com/coder/coder/releases/tag/v2.33.3
  - https://github.com/coder/coder/releases/tag/v2.32.2
  - https://github.com/coder/coder/releases/tag/v2.31.12
  - https://github.com/coder/coder/releases/tag/v2.30.8
  - https://github.com/coder/coder/releases/tag/v2.29.13
  - https://github.com/coder/coder/releases/tag/v2.24.5
  - https://registry.terraform.io/providers/coder/coder/latest/docs/resources/agent#auth-1
rules:
  - title: Detect CVE-2026-46354 Exploitation — Suspicious POST to Azure Instance Identity Endpoint
    description: Detects CVE-2026-46354 exploitation — HTTP POST to /api/v2/workspaceagents/azure-instance-identity which may indicate an attempt to exploit the PKCS#7 signature bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Coder Workspace Agent Git SSH Key Access
    description: Detects access to the /workspaceagents/me/gitsshkey endpoint, potentially indicating an attempt to steal the Git SSH private key after a successful exploit.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect Coder Workspace Agent External Auth Access
    description: Detects access to the /workspaceagents/me/external-auth endpoint, potentially indicating an attempt to steal OAuth access tokens after a successful exploit.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.005
    data_sources:
      - webserver
rules_count: 3
---

Coder v2 is susceptible to a critical vulnerability where the `azureidentity.Validate()` function fails to properly validate the PKCS#7 signature when using Azure instance identity for authentication. This flaw allows an unauthenticated attacker to bypass security measures by embedding a legitimate Azure certificate alongside a forged `vmId` within a PKCS#7 envelope. Successful exploitation allows retrieval of the victim workspace agent's session token, granting unauthorized access to sensitive resources. The attacker only requires knowledge of the target VM's `vmId` (UUIDv4), which, while a limitation, could be obtained through prior access or reconnaissance. This vulnerability impacts all versions of Coder v2 prior to the patched versions released in May 2026.

## Attack Chain

1. Attacker identifies a target Coder workspace agent and obtains its `vmId` UUIDv4.
2. Attacker crafts a malicious PKCS#7 envelope containing a legitimate Azure certificate and a forged `vmId` targeting the identified workspace.
3. Attacker sends a `POST` request to the `/api/v2/workspaceagents/azure-instance-identity` endpoint with the crafted PKCS#7 envelope. This endpoint is unauthenticated.
4. Coder's `azureidentity.Validate()` function incorrectly validates only the signer certificate, failing to verify the PKCS#7 signature itself.
5. The forged `vmId` is accepted, and the attacker retrieves the workspace agent's session token.
6. Attacker uses the stolen token to access the `GET /workspaceagents/me/gitsshkey` endpoint to retrieve the Git SSH private key.
7. Attacker uses the stolen token to access `GET /workspaceagents/me/external-auth` endpoint, exfiltrating OAuth access tokens for GitHub, GitLab, and Bitbucket.
8. Attacker uses the stolen token to access workspace secrets via the agent manifest, including environment variables, file paths, and API keys.

## Impact

Successful exploitation of this vulnerability (CVE-2026-46354) grants an attacker unauthorized access to sensitive resources within Coder workspaces. This can lead to complete compromise of the workspace, including the ability to push malicious code to repositories using the stolen Git SSH private key, impersonate the workspace owner, and access sensitive environment variables, file paths, and API keys. If an attacker gains access to source code repositories and developer secrets, they can cause significant data breaches, intellectual property theft, and supply chain attacks.

## Recommendation

*   Immediately patch Coder instances to the latest versions (>= v2.33.3, v2.32.2, v2.31.12, v2.30.8, v2.29.13, v2.24.5) to address CVE-2026-46354.
*   As a temporary workaround, reconfigure Azure templates to use token authentication instead of `azure-instance-identity`, as described in the advisory. Specifically, modify the [`coder_agent.auth`](https://registry.terraform.io/providers/coder/coder/latest/docs/resources/agent#auth-1) value to `token`.
*   Implement the provided Sigma rule to detect suspicious POST requests to the `/api/v2/workspaceagents/azure-instance-identity` endpoint with potentially crafted PKCS#7 envelopes.
*   Monitor web server logs for abnormal activity and unauthorized access attempts to the `/api/v2/workspaceagents/azure-instance-identity`, `/workspaceagents/me/gitsshkey`, and `/workspaceagents/me/external-auth` endpoints.
