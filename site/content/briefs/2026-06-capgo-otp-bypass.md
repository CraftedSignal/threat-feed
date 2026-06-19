---
title: 'CVE-2026-56073: Cap-go OTP Verification Authentication Bypass'
slug: 2026-06-capgo-otp-bypass
description: Cap-go versions prior to 12.128.2 are susceptible to an authentication bypass vulnerability (CVE-2026-56073) in OTP verification that allows attackers to manipulate server responses to falsely mark verification successful, leading to unauthorized 2FA enablement and subsequent account takeover.
date: "2026-06-19T22:26:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - web-application
  - vulnerability
  - cap-go
  - account-takeover
  - cve
  - network-attack
vendors:
  - Cap-go
products:
  - Cap-go (< 12.128.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Compromise Accounts
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56073
  - https://github.com/Cap-go/capgo/security/advisories/GHSA-x2gq-85v8-j9v4
  - https://www.vulncheck.com/advisories/cap-go-otp-bypass-via-response-manipulation-in-email-verification
rules:
  - title: 'CVE-2026-56073: Cap-go Direct OTP/Email Status Assertion Attempt'
    description: Detects CVE-2026-56073 exploitation — HTTP POST requests to Cap-go's OTP or email verification endpoints (`/api/otp/verify`, `/api/email/verify`, or similar) that contain query parameters or request body content explicitly attempting to force a 'status=success' or 'verified=true' state, indicative of a potential authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1190
      - T1556.006
    data_sources:
      - webserver
  - title: 'CVE-2026-56073: Cap-go Anomalous 2FA/Email Update Client'
    description: Detects successful 2FA enablement or email update requests on Cap-go from client User-Agents or HTTP Referers indicating automated or non-standard access. This pattern could be consistent with post-exploitation of CVE-2026-56073 to effect unauthorized account changes after bypassing OTP verification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1071.001
      - T1556.006
    data_sources:
      - webserver
rules_count: 2
---

A critical authentication bypass vulnerability, identified as CVE-2026-56073, exists in Cap-go versions prior to 12.128.2. This flaw specifically affects the One-Time Password (OTP) and email verification processes, allowing malicious actors to circumvent these security controls. Attackers can intercept HTTP responses from the Cap-go server during an OTP or email verification attempt and modify them to falsely indicate successful verification. This manipulation tricks the client-side application (and potentially the server if it relies on client-reported state) into believing a valid OTP was provided. This enables unauthorized two-factor authentication (2FA) enablement or other sensitive account actions, with a high potential for full account takeover. The vulnerability has a CVSS v3.1 base score of 9.4, highlighting its severe impact and the urgent need for remediation.

## Attack Chain

1.  **Initial Access:** An attacker first gains access to a Cap-go user account, typically through compromised credentials (e.g., via phishing, credential stuffing, or leaked passwords).
2.  **Initiate Verification Process:** The attacker (or a legitimate user whose session is under attack) attempts to perform an action requiring OTP or email verification, such as enabling 2FA, changing the account's primary email address, or resetting a password.
3.  **Server Response Interception:** The Cap-go server sends an HTTP response to the client regarding the status of the OTP or email verification (e.g., indicating an invalid OTP, awaiting input, or an error). The attacker intercepts this response in transit, potentially via a Man-in-the-Middle (MiTM) attack, a compromised client, or by manipulating client-side logic.
4.  **Response Manipulation:** The attacker modifies the intercepted HTTP response to falsely indicate a successful OTP or email verification, overriding the server's legitimate response. This manipulation occurs without providing a valid OTP or fulfilling the actual verification requirements.
5.  **Forward Manipulated Response:** The attacker forwards the falsified HTTP response to the client application.
6.  **Client-Side Processing:** The Cap-go client application receives and processes the manipulated response, erroneously believing that the OTP or email verification was legitimately successful.
7.  **Unauthorized Action Request:** Based on the client's now "verified" state, the client sends subsequent HTTP requests to the Cap-go server to complete the sensitive action (e.g., confirming 2FA enablement, finalizing an email address change).
8.  **Account Takeover:** The Cap-go server processes the client's request, and due to insufficient verification of the preceding OTP or email verification state (CWE-345), it grants the unauthorized 2FA enablement or account change, leading to full account takeover by the attacker.

## Impact

The successful exploitation of CVE-2026-56073 leads to severe security consequences, primarily centered on unauthorized account access and potential account takeover. With a CVSS v3.1 base score of 9.4, the vulnerability poses a critical risk to the confidentiality, integrity, and availability of user accounts. Attackers can effectively bypass crucial multi-factor authentication mechanisms, gain complete control over compromised user accounts, and potentially access sensitive data or functionalities within the Cap-go environment. This could result in unauthorized data exfiltration, fraudulent transactions, or further compromise of integrated systems. Organizations utilizing affected Cap-go versions face substantial reputational damage, potential compliance violations, and direct financial losses due to widespread account compromises and data breaches.

## Recommendation

*   Immediately patch all Cap-go instances to version 12.128.2 or later to remediate CVE-2026-56073.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, focusing on `/api/otp/verify`, `/api/email/verify`, `/api/2fa/enable`, and `/auth/update` endpoints.
*   Implement strong network monitoring for unusual HTTP response modifications, particularly for authentication-related traffic, to detect potential Man-in-the-Middle attacks.
*   Review web server and application logs for `HTTP POST` requests to sensitive account modification endpoints (e.g., `/api/2fa/enable`, `/api/user/email`) that exhibit anomalous client characteristics (e.g., suspicious User-Agents or Referers) or occur without a typical preceding authentication and OTP verification flow.
