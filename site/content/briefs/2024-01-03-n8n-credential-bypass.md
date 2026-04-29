---
title: n8n Credential Authorization Bypass in dynamic-node-parameters Allows Foreign API Key Replay
slug: 2024-01-03-n8n-credential-bypass
description: A credential authorization bypass vulnerability in n8n versions before 2.18.0 allows an authenticated user with access to a shared workflow to supply a foreign credential ID, causing the backend to decrypt and use that credential against attacker-controlled infrastructure, leading to API key exfiltration.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - credential-access
  - authorization-bypass
  - n8n
vendors:
  - n8n
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-r4v6-9fqc-w5jr
rules:
  - title: Detect n8n Foreign Credential ID in dynamic-node-parameters
    description: Detects attempts to use a foreign credential ID in n8n's dynamic-node-parameters endpoints, indicating a potential credential authorization bypass exploit.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect n8n API Request to Attacker Controlled Infrastructure
    description: Detects n8n making API requests to suspicious or attacker-controlled infrastructure
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A credential authorization bypass vulnerability, identified as CVE-2026-42226, affects n8n versions prior to 2.18.0, specifically in the `dynamic-node-parameters` endpoints. This flaw allows an authenticated user who has access to a shared workflow to exploit the system by supplying a credential ID belonging to another user in the request body. Due to insufficient validation, the n8n backend decrypts and utilizes the specified credential during a helper execution path where the caller controls the destination URL. This enables the malicious user to force the n8n instance to authenticate against attacker-controlled infrastructure using another user's credentials, effectively exfiltrating a reusable API key. The vulnerability impacts any node that dynamically resolves credentials through the affected endpoints. The issue was patched in n8n version 2.18.0.

## Attack Chain

1. An attacker gains authenticated access to an n8n instance.
2. The attacker obtains access to a shared workflow.
3. The attacker identifies a credential ID belonging to another user within the n8n instance.
4. The attacker crafts a request to a vulnerable `dynamic-node-parameters` endpoint, injecting the foreign credential ID into the request body.
5. The n8n backend, failing to validate the attacker's authorization to use the specified credential, decrypts the targeted credential.
6. The attacker controls the destination URL in the request, pointing it to attacker-controlled infrastructure.
7. The n8n backend authenticates against the attacker-controlled infrastructure using the decrypted credential, sending the API key to the attacker.
8. The attacker captures the API key and uses it to access resources or data accessible to the compromised credential.

## Impact

Successful exploitation of this vulnerability (CVE-2026-42226) allows an attacker to exfiltrate API keys belonging to other n8n users. This can lead to unauthorized access to external services and data, depending on the permissions granted to the compromised credentials. The impact is significant, potentially affecting all n8n instances running vulnerable versions (prior to 2.18.0). The severity is rated as high due to the ease of exploitation and the potential for significant data breaches.

## Recommendation

*   Upgrade n8n to version 2.18.0 or later to patch the vulnerability (CVE-2026-42226).
*   Deploy the Sigma rule `Detect n8n Foreign Credential ID in dynamic-node-parameters` to identify attempts to exploit this vulnerability.
*   Implement stricter access controls and limit workflow sharing to trusted users as a short-term mitigation, as suggested in the overview.
