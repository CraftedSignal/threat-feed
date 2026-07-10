---
title: blueprintUE Password Reset Token Vulnerability (CVE-2026-40585)
slug: 2024-01-03-blueprintue-password-reset
description: blueprintUE versions before 4.2.0 generate password reset tokens that remain valid indefinitely due to the absence of a timestamp validation, allowing attackers to potentially gain unauthorized access via token reuse.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-40585
  - password-reset
  - blueprintUE
vendors:
  - blueprintUE
products:
  - blueprintUE
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2026-40585
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40585
rules:
  - title: Detect Password Reset Request from Unusual IP
    description: Detects password reset requests originating from IP addresses not commonly associated with the targeted user.  Requires a baseline of normal IP addresses for each user.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - network_connection
      - windows
  - title: Detect BlueprintUE Password Reset Endpoint Access
    description: Detects access to BlueprintUE password reset endpoint. Useful for identifying potential password reset attacks.
    platform: sigma
    severity: informational
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
rules_count: 2
---

blueprintUE, a tool used by Unreal Engine developers, contains a vulnerability in its password reset mechanism in versions prior to 4.2.0. When a user initiates a password reset, the application generates a 128-character cryptographically secure pseudo-random number generator (CSPRNG) token and stores it alongside a password_reset_at timestamp. The vulnerability, identified as CVE-2026-40585, stems from the `findUserIDFromEmailAndToken()` function, which only verifies the email address and reset token but fails to check the validity of the `password_reset_at` timestamp. Consequently, a generated reset token remains valid indefinitely until it is either used for a password reset or overwritten by a subsequent password reset request. This issue is resolved in blueprintUE version 4.2.0. Defenders should prioritize identifying and upgrading vulnerable blueprintUE instances to version 4.2.0 or later.

## Attack Chain

1.  An attacker identifies a user of a vulnerable blueprintUE instance.
2.  The attacker triggers a password reset for the target user's account. This generates a reset token and a timestamp which are stored by blueprintUE.
3.  The attacker intercepts the password reset email sent to the target user. (This is an assumption as the source does not explicitly mention how the attacker obtains the token.)
4.  The target user, unaware of the attacker's actions, may also initiate a password reset, generating a new token and invalidating the first one (if it hadn't already been used).
5.  The attacker, possessing a valid (or previously valid) password reset token, crafts a malicious password reset request.
6.  The `findUserIDFromEmailAndToken()` function processes the request, validates the email and token against the stored values, but fails to check the `password_reset_at` timestamp.
7.  Due to the missing timestamp validation, the system incorrectly identifies the attacker as the legitimate owner of the account.
8.  The attacker successfully resets the user's password and gains unauthorized access to their blueprintUE account.

## Impact

Successful exploitation of this vulnerability, tracked as CVE-2026-40585, allows an attacker to gain unauthorized access to a blueprintUE user's account. The number of potential victims is dependent on the number of blueprintUE instances running versions prior to 4.2.0 and the number of active users on those instances. If successful, the attacker could potentially access and modify Unreal Engine projects, intellectual property, and other sensitive data associated with the compromised account. The impact could range from minor disruptions to significant financial losses, depending on the sensitivity and value of the accessed information.

## Recommendation

*   Upgrade all blueprintUE instances to version 4.2.0 or later to remediate CVE-2026-40585.
*   Implement web server access logging to monitor for unusual password reset requests targeting specific accounts. Analyze webserver logs for POST requests to password reset endpoints (`webserver`, `linux`).
*   Deploy the Sigma rule to detect password reset requests originating from unusual or suspicious IP addresses (`network_connection`, `windows`).
