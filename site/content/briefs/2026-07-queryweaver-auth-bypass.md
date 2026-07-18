---
title: QueryWeaver Authentication Bypass via Signup Request (CVE-2026-10130)
slug: 2026-07-queryweaver-auth-bypass
description: CVE-2026-10130 describes an authentication bypass vulnerability in QueryWeaver, enabling unauthenticated attackers to obtain valid session tokens for existing user accounts by submitting a crafted signup request with a known victim's email address, leveraging a Cypher MERGE operation that unconditionally links a new token before checking for existing accounts.
date: "2026-07-18T23:17:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - cve
  - web-vulnerability
  - queryweaver
products:
  - QueryWeaver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated attackers to obtain valid session tokens for existing accounts by submitting a signup request
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: server to return a valid authenticated session token for the victim's identity without requiring any prior credentials or user interaction.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: server to return a valid authenticated session token for the victim's identity without requiring any prior credentials or user interaction.
    confidence_band: high
cves:
  - id: CVE-2026-10130
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10130
---

A critical authentication bypass vulnerability, identified as CVE-2026-10130, exists in the QueryWeaver application. This flaw allows unauthenticated attackers to gain unauthorized access to existing user accounts. The vulnerability stems from the application's signup process: when a signup request is submitted with an email address corresponding to an existing user, QueryWeaver's underlying Cypher MERGE operation unconditionally creates and links a new session token to that user's identity *before* verifying if the email already belongs to an existing account. As a result, the server returns a valid, authenticated session token directly to the attacker, completely bypassing any credential checks or user interaction, posing a significant risk to user data confidentiality and integrity. The vulnerability affects QueryWeaver instances where users can register.

## Attack Chain

1. Attacker identifies a vulnerable QueryWeaver application instance.
2. Attacker gathers publicly available or leaked information to identify a legitimate victim's email address associated with an existing QueryWeaver account.
3. Attacker crafts and sends an HTTP POST request to the QueryWeaver application's signup route, including the victim's known email address in the request.
4. The QueryWeaver application processes the signup request internally.
5. Due to the vulnerability, the application performs a Cypher MERGE operation that generates a new session token and links it to the existing user identity corresponding to the provided email, without prior authentication checks.
6. The QueryWeaver server responds to the attacker's signup request, inadvertently returning the newly generated, valid authenticated session token associated with the victim's account.
7. The attacker extracts and utilizes the obtained session token in subsequent requests to the QueryWeaver application.
8. The attacker successfully bypasses authentication and gains full unauthorized access to the victim's QueryWeaver account, impersonating the legitimate user.

## Impact

Successful exploitation of CVE-2026-10130 grants unauthenticated attackers full control over victim accounts within the QueryWeaver application. This can lead to severe data breaches, including the exposure of sensitive personal and organizational data, financial fraud if linked to payment systems, and reputational damage. Attackers can view, modify, or delete account data, send messages, or perform any actions the legitimate user is authorized to perform. While specific victim counts or targeted sectors are not available in the provided information, any organization using QueryWeaver is at risk, particularly those handling confidential or critical data.

## Recommendation

* **Patch CVE-2026-10130 immediately** by applying the latest security updates provided by the QueryWeaver vendor to all deployments.
* **Implement HTTP logging** for the QueryWeaver webserver to monitor for suspicious or high volumes of signup attempts, especially those leading to immediate successful session establishment from unusual source IPs.
* **Monitor authentication logs** for QueryWeaver for unusual session activity associated with existing accounts that did not involve a prior login event, potentially indicating an authentication bypass.
