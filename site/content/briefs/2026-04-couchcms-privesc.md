---
title: CouchCMS Privilege Escalation via f_k_levels_list Parameter Manipulation (CVE-2026-29002)
slug: 2026-04-couchcms-privesc
description: CouchCMS is vulnerable to privilege escalation, allowing authenticated Admin-level users to create SuperAdmin accounts by manipulating the 'f_k_levels_list' parameter during user creation, granting them full application control.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - web-application
  - cve
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-29002
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29002
  - https://gist.github.com/thepiyushkumarshukla/477e2d2bbbe8cc3ec0d640c50f0cf9e1
  - https://www.couchcms.com/
  - https://www.vulncheck.com/advisories/couchcms-privilege-escalation-via-f-k-levels-list-parameter
rules:
  - title: Detect CouchCMS SuperAdmin Creation via Parameter Tampering
    description: Detects attempts to create SuperAdmin accounts in CouchCMS by tampering with the f_k_levels_list parameter.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect CouchCMS Admin Panel Access
    description: Detects access to the CouchCMS administration panel login page.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-29002 identifies a privilege escalation vulnerability in CouchCMS. This flaw allows authenticated users with Admin-level privileges to elevate their access to SuperAdmin by tampering with the `f_k_levels_list` parameter during the user creation process. By modifying the value of this parameter from "4" to "10" in the HTTP request body, an attacker can bypass authorization checks, effectively circumventing restrictions on SuperAdmin account creation and privilege assignment. This vulnerability allows the attacker to gain complete control over the CouchCMS application. Successful exploitation requires valid Admin-level credentials and the ability to modify HTTP request parameters.

## Attack Chain

1. An attacker obtains valid Admin-level credentials for a CouchCMS instance.
2. The attacker navigates to the user creation page within the CouchCMS admin panel.
3. The attacker intercepts the HTTP request generated when submitting the user creation form.
4. The attacker modifies the `f_k_levels_list` parameter in the HTTP request body, changing its value from "4" (Admin) to "10" (SuperAdmin).
5. The attacker submits the modified HTTP request to the CouchCMS server.
6. The CouchCMS server, due to insufficient authorization validation, creates a new user account with SuperAdmin privileges.
7. The attacker logs in with the newly created SuperAdmin account.
8. The attacker gains full control over the CouchCMS application, including the ability to modify system settings, access sensitive data, and potentially compromise the underlying server.

## Impact

Successful exploitation of CVE-2026-29002 leads to complete compromise of the CouchCMS application. An attacker with SuperAdmin privileges can access and modify any data within the CMS, potentially defacing websites, stealing sensitive information, or disrupting services. The vulnerability affects all CouchCMS installations where user creation is enabled and accessible to Admin-level users.

## Recommendation

*   Apply the patch or upgrade to a version of CouchCMS that addresses CVE-2026-29002.
*   Deploy the Sigma rule `Detect CouchCMS SuperAdmin Creation via Parameter Tampering` to your SIEM to detect attempts to exploit this vulnerability.
*   Monitor web server logs for POST requests to the user creation endpoint with a modified `f_k_levels_list` parameter.
*   Implement strict input validation and authorization checks on the server-side to prevent unauthorized modification of user privileges.
