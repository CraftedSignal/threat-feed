---
title: FastGPT NoSQL Injection Vulnerability in Password Change Endpoint
slug: 2026-04-fastgpt-nosql
description: FastGPT versions prior to 4.14.9.5 are vulnerable to NoSQL injection in the password change endpoint, allowing authenticated attackers to bypass password verification and perform account takeover.
date: "2026-04-17T22:16:32Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - nosql-injection
  - account-takeover
  - cve
  - fastgpt
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-40352
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40352
rules:
  - title: Detect FastGPT Password Reset Bypass
    description: Detects potential NoSQL injection attempts to bypass the password verification during password reset in FastGPT.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect FastGPT Password Reset Endpoint Access
    description: Detects access to the FastGPT password reset endpoint, which could be indicative of account takeover attempts.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FastGPT, an AI Agent building platform, is susceptible to a critical NoSQL injection vulnerability affecting versions before 4.14.9.5. The flaw resides within the password change endpoint, enabling an authenticated attacker to circumvent the necessary "old password" verification process. By injecting MongoDB query operators, an attacker with an existing, low-privileged session can manipulate password changes for their own account, or potentially other accounts if combined with ID manipulation techniques. This exploit leads to full account takeover, allowing attackers to maintain persistence and potentially compromise sensitive data. This vulnerability has been patched in version 4.14.9.5, urging users to upgrade immediately.

## Attack Chain

1.  Attacker gains initial access to a FastGPT account with low privileges through legitimate means (e.g., registration or stolen credentials).
2.  Attacker navigates to the password change endpoint within the FastGPT application.
3.  The attacker crafts a malicious request to the password change endpoint, injecting MongoDB query operators into the "old password" field. For example, using a payload like `{$ne: "legitimate_old_password"}`.
4.  The application's backend improperly processes the injected query operators, failing to correctly validate the old password against the stored hash.
5.  The attacker provides a new password and confirms it within the crafted request.
6.  The FastGPT application updates the account's password in the database, replacing the original password with the attacker-controlled value.
7.  The attacker logs out and logs back in using the newly set password, gaining full control of the compromised account.
8.  The attacker leverages the compromised account to access sensitive data, modify configurations, or perform other malicious activities within the FastGPT platform.

## Impact

Successful exploitation of this vulnerability allows attackers to take complete control of FastGPT accounts. The consequences range from unauthorized access to sensitive data and configurations to potential manipulation of AI agent behavior. This account takeover can lead to data breaches, service disruption, and reputational damage. While the specific number of victims is unknown, any FastGPT instance running a version prior to 4.14.9.5 is vulnerable, potentially affecting a wide range of users and organizations. The CVSS v3.1 base score of 8.8 highlights the severity of this issue.

## Recommendation

*   Immediately upgrade all FastGPT installations to version 4.14.9.5 or later to patch the NoSQL injection vulnerability (CVE-2026-40352).
*   Implement the Sigma rule `Detect FastGPT Password Reset Bypass` to detect potential exploitation attempts against the password change endpoint.
*   Review FastGPT webserver logs for unusual patterns or MongoDB query operators within requests to the password change endpoint to identify potential compromises.
*   Enable and review detailed webserver logging for FastGPT to increase visibility into HTTP requests.
