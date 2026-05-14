---
title: ApostropheCMS Account Takeover via Weak Password Reset Mechanism (CVE-2026-45013)
slug: 2026-05-weak-password-reset
description: ApostropheCMS is vulnerable to account takeover due to a weak password recovery mechanism; the password reset flow constructs the reset URL using `req.hostname`, derived from the attacker-controlled HTTP `Host` header when `apos.baseUrl` is not explicitly configured, enabling account takeover if the victim clicks a malicious password reset link.
date: "2026-05-14T18:30:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - weak-password
  - account-takeover
vendors:
  - Apostrophe
products:
  - apostrophecms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
references:
  - https://github.com/advisories/GHSA-gf43-24g3-5hw2
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection
  - https://cwe.mitre.org/data/definitions/640.html
rules:
  - title: Detect ApostropheCMS Weak Password Reset Request
    description: Detects CVE-2026-45013 exploitation — Monitors password reset requests to `/api/v1/login/reset-request` with a non-standard Host header, indicating a potential account takeover attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Access to Password Reset URL
    description: Detects access to a password reset URL from an attacker-controlled host, suggesting that a user may have clicked on a malicious link.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - webserver
rules_count: 2
---

ApostropheCMS is vulnerable to a critical account takeover flaw (CVE-2026-45013) stemming from a weak password reset implementation. The vulnerability resides in `modules/@apostrophecms/login/index.js` within the `resetRequest` route. The issue arises when `apos.baseUrl` is not explicitly configured, causing the application to construct the password reset URL using the `Host` header of the incoming HTTP request. This allows an unauthenticated attacker, knowing a victim's email address, to craft a password reset request that directs the victim to a malicious domain under the attacker's control. The victim unknowingly provides the valid reset token to the attacker when clicking the link, enabling full account takeover. This vulnerability affects ApostropheCMS versions up to and including 4.29.0. It matters for defenders because successful exploitation requires minimal attacker effort and can lead to significant data breaches or unauthorized access.

## Attack Chain

1. The attacker identifies a valid user's email address, potentially through publicly accessible information on the target website.
2. The attacker crafts an HTTP POST request to the `/api/v1/login/reset-request` endpoint, setting the `Host` header to a domain they control (e.g., `evil.attacker.com`). The request body includes the victim's email address in JSON format.
3. The server, lacking a configured `apos.baseUrl`, uses the attacker-controlled `Host` header to generate a password reset link.
4. The application sends a password reset email to the victim, containing a URL that points to the attacker's domain. This URL includes a valid, server-generated reset token and the victim's email address as query parameters.
5. The victim, believing the email to be legitimate, clicks the malicious link.
6. The victim's browser sends a GET request to the attacker's server, including the valid reset token and email address in the query parameters.
7. The attacker's server captures the reset token and email address from the incoming request.
8. The attacker uses the captured token and email address to submit a password reset request to the legitimate `/api/v1/login/reset` endpoint, setting a new password for the victim's account, resulting in full account takeover.

## Impact

Successful exploitation of CVE-2026-45013 allows an attacker to gain full control of any user account for which they know the email address. This can lead to unauthorized access to sensitive data, modification of website content, and potential further compromise of the entire ApostropheCMS instance. The vulnerability requires no authentication and minimal interaction from the victim, making it easily exploitable at scale. The impact is especially high for deployments where `apos.baseUrl` is not configured, which is common in development environments and some production setups.

## Recommendation

*   Immediately configure the `apos.baseUrl` option in your ApostropheCMS deployment to mitigate CVE-2026-45013, as described in the advisory's "Remediation" section. This will prevent the application from using the attacker-controlled `Host` header when generating password reset URLs.
*   Deploy the Sigma rule "Detect ApostropheCMS Weak Password Reset Request" to identify attempted exploitation by monitoring for password reset requests with a suspicious Host header.
*   Deploy the Sigma rule "Detect Access to Password Reset URL" to detect when a user clicks on a password reset link from an attacker-controlled host.
