---
title: Webkul Krayin CRM BOLA Vulnerability (CVE-2026-38529)
slug: 2026-04-krayin-bola
description: CVE-2026-38529 is a Broken Object-Level Authorization (BOLA) vulnerability in Webkul Krayin CRM v2.2.x that allows authenticated attackers to reset user passwords and take over accounts.
date: "2026-04-14T16:16:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - bola
  - cve-2026-38529
  - krayin-crm
  - account-takeover
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-38529
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-38529
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2026-38529
  - https://github.com/krayin/laravel-crm
rules:
  - title: Detect Krayin CRM Password Reset via UserController
    description: Detects password reset attempts on the /Settings/UserController.php endpoint in Krayin CRM, indicative of CVE-2026-38529 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1555
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect Krayin CRM UserController Access
    description: Detects access to the /Settings/UserController.php endpoint in Krayin CRM. Requires further analysis to determine if it is malicious activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-38529 describes a Broken Object-Level Authorization (BOLA) vulnerability affecting Webkul Krayin CRM version 2.2.x. The vulnerability resides in the `/Settings/UserController.php` endpoint. An authenticated attacker can exploit this flaw by sending a crafted HTTP request. Successful exploitation allows the attacker to arbitrarily reset the passwords of other users, leading to complete account takeover. Given the potential for widespread compromise and data breaches, this vulnerability poses a critical risk to organizations using the affected Krayin CRM version. Publicly available information regarding exploitation is available on GitHub.

## Attack Chain

1.  The attacker authenticates to the Krayin CRM application with valid credentials.
2.  The attacker crafts a malicious HTTP request targeting the `/Settings/UserController.php` endpoint.
3.  The crafted request is designed to reset the password of a target user, specifying the target user's ID.
4.  Due to the BOLA vulnerability, the application fails to properly validate if the authenticated user has the authorization to modify the target user's password.
5.  The application resets the target user's password using the attacker-supplied data.
6.  The attacker uses the new password to log in to the target user's account.
7.  The attacker gains full control over the target user's account and data.

## Impact

Successful exploitation of CVE-2026-38529 allows attackers to compromise user accounts within a Webkul Krayin CRM v2.2.x instance. This can lead to unauthorized access to sensitive customer data, business records, and other confidential information. A successful attack could result in data breaches, financial loss, reputational damage, and legal liabilities. Given the potential for complete account takeover, the impact is considered critical for organizations using the vulnerable CRM.

## Recommendation

*   Apply the patch or upgrade to a secure version of Krayin CRM that addresses CVE-2026-38529 as soon as it becomes available.
*   Implement the Sigma rule `Detect Krayin CRM Password Reset via UserController` to detect exploitation attempts targeting the vulnerable endpoint.
*   Review and enforce strict access control policies within the Krayin CRM application to prevent unauthorized modification of user accounts.
*   Monitor web server logs for suspicious activity targeting the `/Settings/UserController.php` endpoint.
*   Enable web server logging to capture detailed information about HTTP requests, including request parameters.
