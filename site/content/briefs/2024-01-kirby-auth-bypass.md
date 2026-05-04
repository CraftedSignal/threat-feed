---
title: Kirby CMS Missing Authorization Vulnerability
slug: 2024-01-kirby-auth-bypass
description: Kirby CMS versions before 4.9.0 and between 5.0.0 and 5.3.3 contain a missing authorization vulnerability, allowing authenticated Panel users to access site model, user, and role information without proper permission checks, potentially leading to unauthorized information disclosure.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization
  - privilege-escalation
  - web-application
vendors:
  - Kirby
products:
  - cms (<= 4.8.0)
  - cms (>= 5.0.0, <= 5.3.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-2h7v-4372-f6x2
  - https://github.com/getkirby/kirby/releases/tag/4.9.0
  - https://github.com/getkirby/kirby/releases/tag/5.4.0
rules:
  - title: Kirby CMS Unauthorized Access to User List
    description: Detects unauthorized access to the Kirby CMS user list, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Kirby CMS Unauthorized Access to Site Configuration
    description: Detects unauthorized attempts to access the Kirby CMS site configuration, potentially indicating information gathering or privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Kirby CMS Unauthorized Access to Roles List
    description: Detects unauthorized attempts to access the Kirby CMS roles list, potentially indicating information gathering or privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Kirby CMS, a file-based content management system, has a missing authorization flaw that allows authenticated users to access sensitive site, user, and role information without the necessary permissions. This vulnerability affects installations where there are potentially untrusted authenticated users. The issue stems from the lack of permission settings controlling access to the site model, users, and user roles. Specifically, the permissions `site.access`, `user.access`, `users.access`, `user.list`, and `users.list` were missing. This vulnerability was reported by @HuajiHD and patched in Kirby versions 4.9.0 and 5.4.0. Sites that explicitly intend all authenticated users to have read access to all site, user, and role information are not affected.

## Attack Chain

1. An attacker obtains valid credentials for a user account with access to the Kirby Panel.
2. The attacker authenticates to the Kirby Panel using their credentials.
3. The attacker crafts a request to access the site model data. This could involve accessing specific API endpoints related to site configuration.
4. The attacker sends a request to list all users within the Kirby CMS.
5. The system, lacking proper authorization checks, returns the requested site model and user list data to the attacker.
6. The attacker sends a request to list existing roles, their names, descriptions, and configured permissions.
7. The system returns the requested role information, again bypassing intended permission restrictions.
8. The attacker gains unauthorized knowledge of the site structure, user accounts, and role permissions, which can be used to escalate privileges or further compromise the system.

## Impact

Successful exploitation of this vulnerability allows an attacker with low-privilege Panel access to enumerate users, roles, and site configurations. This information can be used to identify privileged accounts, understand the site's structure, and potentially escalate privileges by exploiting other vulnerabilities or misconfigurations. This impacts all Kirby sites using versions <= 4.8.0 and versions >= 5.0.0 and <= 5.3.3 where authenticated users are not fully trusted.

## Recommendation

*   Upgrade to Kirby version 4.9.0 or 5.4.0 or later to patch the vulnerability as described in the advisory.
*   Review user roles and permissions after upgrading to ensure appropriate access controls are in place.
*   Monitor web server logs for suspicious requests targeting user and role enumeration endpoints after deploying the below rules.
