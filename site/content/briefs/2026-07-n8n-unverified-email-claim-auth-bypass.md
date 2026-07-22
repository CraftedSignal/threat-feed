---
title: n8n Account Takeover via Unverified Email Claim in Token Exchange Embed Login
slug: 2026-07-n8n-unverified-email-claim-auth-bypass
description: A high-severity vulnerability in n8n's embed login feature (CVE-2026-XXXX) allows attackers to achieve full account takeover by leveraging unverified email claims in incoming tokens, enabling authentication as any existing user if the instance has embed login enabled and a trusted key source configured that emits unverified email addresses.
date: "2026-07-22T22:05:38Z"
lastmod: "2026-07-22T22:18:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authentication-bypass
  - account-takeover
  - n8n
  - embed-login
  - credential-access
  - exfiltration
  - rce
  - sandbox-escape
  - javascript
vendors:
  - n8n GmbH
products:
  - n8n (< 2.31.5)
  - n8n (>= 2.32.0, < 2.32.1)
  - n8n (2.32.0)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: anyone able to obtain a token accepted by one of the configured trusted keys, for example a trusted issuer that emitted unverified email addresses, could authenticate as any existing user
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: could authenticate as any existing user, gaining full account control
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: gaining full account control
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A low-privileged workflow editor with use-only access to such a shared credential could point one of these nodes at an attacker-controlled host and cause the credential secret to be transmitted there
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: cause the credential secret to be transmitted there, then reuse it against the underlying service.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated user with permission to create or modify workflows could abuse crafted expressions using arrow functions to bypass the expression sandbox, triggering unintended system command execution on the host running n8n.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: An authenticated user with permission to create or modify workflows could abuse crafted expressions using arrow functions to bypass the expression sandbox, triggering unintended system command execution on the host running n8n.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8342-988q-86cr
  - https://github.com/advisories/GHSA-64xh-79j6-r5v8
  - https://github.com/advisories/GHSA-gv7g-jm28-cr3m
rules:
  - title: Detect n8n (Node.js) Spawning Suspicious Windows Shell Process
    description: Detects CVE-202X-XXXX exploitation where n8n (Node.js) process on Windows spawns suspicious shell or command execution processes, indicative of RCE due to sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1210
    data_sources:
      - process_creation
      - windows
  - title: Detect n8n (Node) Spawning Suspicious Linux Shell Process
    description: Detects CVE-202X-XXXX exploitation where n8n (Node) process on Linux spawns suspicious shell or command execution processes, indicative of RCE due to sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1210
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-07-22T22:11:47Z"
    level: L2
    summary: 'merged source coverage: n8n Credential Restriction Bypass in AI/LLM Nodes Leading to Secret Exfiltration'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-64xh-79j6-r5v8
  - at: "2026-07-22T22:18:03Z"
    level: L2
    summary: 'added detection rule: Detect n8n (Node.js) Spawning Suspicious Windows Shell Process'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-gv7g-jm28-cr3m
---

A high-severity authentication bypass vulnerability has been identified in the workflow automation platform n8n, affecting versions prior to 2.31.5 and between 2.32.0 and 2.32.1. This flaw, present when the embed login feature is enabled and at least one trusted key source is configured, allows an attacker to achieve full account takeover. Specifically, if a trusted identity provider issues tokens containing unverified email claims, n8n's token exchange mechanism fails to validate that the trusted key's permitted role ceiling covers the account or that the email claim itself is verified. This oversight enables an adversary to forge or intercept a validly-signed token from such an issuer and authenticate as any existing n8n user by matching the unverified email claim to a local account. This vulnerability poses a critical risk to data integrity and access control for affected n8n instances.

## Attack Chain

1. **Initial Reconnaissance:** Attacker identifies a vulnerable n8n instance with the embed login feature enabled and at least one trusted key source configured.
2. **Trusted Issuer Identification:** Attacker identifies a configured trusted identity provider that issues tokens which include unverified email claims.
3. **Token Acquisition/Forgery:** Attacker obtains a validly-signed token from the identified trusted issuer, potentially by exploiting a weakness in the issuer itself or by crafting a token with an unverified email claim matching an existing n8n user.
4. **Impersonation Attempt:** The attacker presents this specially crafted token to the n8n instance's embed login endpoint, claiming the identity of an existing n8n user via the unverified email claim.
5. **Authentication Bypass:** Due to the vulnerability, n8n fails to verify the email claim's validity or the trusted key's role ceiling against the target account, and mistakenly authenticates the attacker.
6. **Account Takeover:** The attacker gains full control over the targeted n8n user's account, including access to workflows, data, and configuration.
7. **Impact on Target:** Attacker can now execute arbitrary workflows, exfiltrate sensitive data, or disrupt business operations.

## Impact

Successful exploitation of this vulnerability leads to full account takeover within the n8n instance. An attacker can authenticate as any existing user, gaining access to all their associated data, workflows, and permissions. This can result in unauthorized data access, modification, or deletion, as well as the execution of malicious automation workflows. The risk is specifically present for n8n instances where the embed login feature is enabled and at least one trusted key source is configured, particularly if those trusted keys are associated with identity providers that emit unverified email addresses.

## Recommendation

* Upgrade n8n instances to version 2.32.1 or later immediately to remediate the vulnerability.
* If immediate upgrade is not possible, disable the embed login feature by setting the environment variable `N8N_TOKEN_EXCHANGE_ENABLED=false`.
* If embed login cannot be disabled, restrict network access to the n8n instance to fully trusted parties only.
* Audit all configured trusted keys and their `allowedRoles` assignments for any unnecessarily broad permissions.
* Review `auth_identity` records for unexpected `token-exchange` entries, especially those linked to high-privilege accounts, as a post-compromise indicator.
