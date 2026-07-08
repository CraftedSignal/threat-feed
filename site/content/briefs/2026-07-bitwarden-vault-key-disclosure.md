---
title: CVE-2026-60104 - Bitwarden Server Vault Key Disclosure and Account Takeover
slug: 2026-07-bitwarden-vault-key-disclosure
description: A low-privileged Bitwarden organization member can exploit CVE-2026-60104 in Bitwarden Server versions prior to 2026.6.0, which allows an attacker to obtain another user's vault key and access token by creating a Trusted Device Encryption authentication request bound to an attacker-controlled public key, leading to account takeover.
date: "2026-07-08T20:20:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve
  - account-takeover
  - credential-access
  - data-disclosure
  - bitwarden
vendors:
  - Bitwarden
products:
  - Bitwarden Server < 2026.6.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanisms
    evidence: allowing a low-privileged organization member to obtain another user's vault key and a victim-scoped access token
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: resulting in disclosure of the victim's vault key and account takeover.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: resulting in disclosure of the victim's vault key and account takeover.
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Defacement
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allowing a low-privileged organization member to obtain another user's vault key and a victim-scoped access token
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: resulting in disclosure of the victim's vault key and account takeover.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: resulting in disclosure of the victim's vault key and account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-60104
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60104
---

CVE-2026-60104 impacts Bitwarden Server versions prior to 2026.6.0, presenting a critical vulnerability that allows low-privileged organization members to compromise other users' accounts. The flaw exists because the server fails to verify the email address provided in a `POST /auth-requests/admin-request` body belongs to the authenticated caller. An attacker can leverage this oversight to initiate a Trusted Device Encryption authentication request for a victim, binding it to a public key controlled by the attacker. Once this request is approved by the victim, the authentication details, including the victim's vault key and a victim-scoped access token, become readable from an unauthenticated endpoint. This ultimately leads to the disclosure of sensitive credentials and allows for a complete account takeover of the targeted user. This vulnerability highlights the importance of rigorous identity verification in API endpoints.

## Attack Chain

1. A low-privileged organization member, acting as an attacker, authenticates to the Bitwarden server.
2. The attacker sends a `POST` request to the `/auth-requests/admin-request` API endpoint.
3. The request body of this `POST` call contains the victim's email address and an attacker-controlled public key, intended to initiate a Trusted Device Encryption authentication request for the victim.
4. The Bitwarden Server, vulnerable to CVE-2026-60104, processes this request without verifying that the email in the request body belongs to the authenticated caller.
5. The victim receives and approves the fraudulent Trusted Device Encryption authentication request initiated by the attacker.
6. Upon approval, the authentication request details, including the victim's vault key and a victim-scoped access token, become accessible from an unauthenticated endpoint.
7. The attacker retrieves the victim's vault key and access token from the publicly accessible endpoint.
8. Using the stolen vault key and access token, the attacker performs an account takeover of the victim's Bitwarden account.

## Impact

Successful exploitation of CVE-2026-60104 results in the complete compromise of a targeted Bitwarden user's account. This includes the disclosure of the victim's highly sensitive vault key, which grants access to all stored passwords and secure notes. Additionally, an access token is compromised, allowing an attacker to impersonate the victim within the Bitwarden ecosystem. The impact is significant for any organization utilizing Bitwarden Server versions prior to 2026.6.0, as any low-privileged organization member could theoretically target higher-privileged users or other members, leading to widespread credential exposure and unauthorized access to critical corporate data.

## Recommendation

* Immediately upgrade Bitwarden Server to version 2026.6.0 or later to patch CVE-2026-60104.
* Review all API endpoint configurations, especially those handling authentication and credential management, to ensure robust identity verification.
