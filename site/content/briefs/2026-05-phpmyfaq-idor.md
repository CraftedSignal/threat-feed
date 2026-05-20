---
title: phpMyFAQ IDOR Allows Admin Account Takeover
slug: 2026-05-phpmyfaq-idor
description: An IDOR vulnerability in phpMyFAQ's Admin API allows any authenticated administrator to change the password of any user account, including SuperAdmin accounts, without authorization verification, leading to privilege escalation.
date: "2026-05-20T15:47:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phpMyFAQ
  - IDOR
  - privilege-escalation
  - account-takeover
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ < 4.1.3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-xvp4-phqj-cjr3
rules:
  - title: Detect phpMyFAQ Admin Password Overwrite
    description: Detects phpMyFAQ admin password overwrite attempts by monitoring PUT requests to the /admin/api/user/overwrite-password endpoint with a userId of 1, indicating a potential IDOR attack targeting the SuperAdmin account.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect phpMyFAQ Admin API Access
    description: Detects access to the phpMyFAQ admin API endpoints.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 2
---

An Insecure Direct Object Reference (IDOR) vulnerability exists in phpMyFAQ versions prior to 4.1.3. The vulnerability is located in the Admin API within the `overwritePassword()` method, which lacks proper authorization checks. Any authenticated administrator, even those with low privileges (USER_EDIT permission), can change the password of any user account, including the SuperAdmin account (userId=1). By manipulating the `userId` parameter in a PUT request to `/admin/api/user/overwrite-password`, an attacker can escalate their privileges to full SuperAdmin control. This poses a significant risk to organizations with multiple admin users and environments requiring privilege separation or multi-tenancy.

## Attack Chain

1. The attacker gains access to a low-privilege admin account, either through legitimate means or by exploiting a separate vulnerability.
2. The attacker identifies the `overwritePassword()` endpoint `/admin/api/user/overwrite-password` and its lack of authorization checks.
3. The attacker requests a CSRF token from an admin page using `curl` and `grep`.
4. The attacker crafts a PUT request to the `/admin/api/user/overwrite-password` endpoint. The request body includes a JSON payload with the target `userId` set to '1' (SuperAdmin), a valid CSRF token, and the desired new password for the SuperAdmin account.
5. The phpMyFAQ application receives the PUT request and, due to the IDOR vulnerability, does not validate whether the requesting admin has permission to modify the target user's password.
6. The `overwritePassword()` method changes the SuperAdmin's password to the attacker-supplied password.
7. The attacker logs in as the SuperAdmin using the newly set password.
8. The attacker now has full control of the phpMyFAQ application and can perform any administrative task.

## Impact

Successful exploitation of this IDOR vulnerability allows an attacker to gain complete control of the phpMyFAQ application. This can lead to data breaches, defacement of the FAQ content, and unauthorized modification of system configurations. Organizations with multiple admin users, where not all should have SuperAdmin access, are particularly vulnerable. In multi-tenant environments, this vulnerability could allow an attacker to compromise all tenants managed by the phpMyFAQ instance.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.3 or later to patch the IDOR vulnerability.
*   Implement the Sigma rule `Detect phpMyFAQ Admin Password Overwrite` to detect potential exploitation attempts (see below).
*   Review and restrict admin privileges based on the principle of least privilege to limit the impact of potential account compromises.
*   Enable multi-factor authentication for all admin accounts to further mitigate the risk of unauthorized access.
