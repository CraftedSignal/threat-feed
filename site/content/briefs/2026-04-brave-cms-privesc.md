---
title: Brave CMS Missing Authorization Leads to Privilege Escalation
slug: 2026-04-brave-cms-privesc
description: Brave CMS versions prior to 2.0.6 are vulnerable to privilege escalation due to a missing authorization check in the update role endpoint, allowing any authenticated user to gain Super Admin privileges.
date: "2026-04-06T20:16:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-35182
  - privilege-escalation
  - web-application
  - brave-cms
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35182
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35182
  - https://github.com/Ajax30/BraveCMS-2.0/security/advisories/GHSA-g58h-mvjw-f4hv
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Brave CMS Unauthorized Role Update
    description: Detects POST requests to the /rights/update-role endpoint without proper authorization, indicating potential privilege escalation attempts in Brave CMS.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Brave CMS Super Admin Creation
    description: Detects requests which result in creation of super admin users.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Brave CMS, an open-source content management system, is susceptible to a critical vulnerability (CVE-2026-35182) affecting versions prior to 2.0.6. The vulnerability stems from a missing authorization check in the `/rights/update-role/{id}` endpoint, specifically within the `routes/web.php` file. The absence of the `checkUserPermissions:assign-user-roles` middleware on the POST route allows any authenticated user, regardless of their current role, to modify account roles. This enables malicious actors or internal users to elevate their privileges to Super Admin, granting them complete control over the CMS. This vulnerability poses a significant risk to organizations utilizing affected versions of Brave CMS, potentially leading to data breaches, system compromise, and unauthorized modifications.

## Attack Chain

1.  An attacker gains initial access to a Brave CMS instance with a valid, low-privilege user account (e.g., via compromised credentials or legitimate registration).
2.  The attacker identifies the vulnerable endpoint `/rights/update-role/{id}` within the `routes/web.php` file.
3.  The attacker crafts a POST request to `/rights/update-role/{id}`, where `{id}` is the user ID of the target account (e.g., their own or another user). The request body includes data to modify the target user's role to 'Super Admin'.
4.  The Brave CMS application, lacking the `checkUserPermissions:assign-user-roles` middleware, processes the request without properly validating the attacker's authorization to modify user roles.
5.  The target user's role is updated to 'Super Admin' in the CMS database.
6.  The attacker, now possessing Super Admin privileges, can access all administrative functions within the Brave CMS.
7.  The attacker can modify website content, install malicious plugins, create new admin accounts, and potentially gain access to the underlying server.
8.  The attacker achieves full control of the Brave CMS instance, leading to potential data exfiltration, defacement, or denial-of-service.

## Impact

Successful exploitation of CVE-2026-35182 can lead to complete compromise of the Brave CMS instance. An attacker gaining Super Admin privileges can modify or delete website content, inject malicious code, access sensitive data, and potentially pivot to other systems on the network. The impact can range from website defacement and data breaches to complete loss of control over the CMS and associated infrastructure. There is no information regarding how many victims are affected.

## Recommendation

*   Upgrade Brave CMS to version 2.0.6 or later to patch CVE-2026-35182.
*   Deploy the Sigma rule "Detect Brave CMS Unauthorized Role Update" to detect exploitation attempts in web server logs.
*   Monitor web server logs for POST requests to the `/rights/update-role/` endpoint lacking proper authorization headers or originating from unusual IP addresses.
*   Review user roles and permissions within Brave CMS to identify and remediate any unauthorized privilege escalations.
