---
title: Weblate Improper Privilege Management via API Endpoint (CVE-2026-34393)
slug: 2026-04-weblate-privilege-escalation
description: Weblate versions prior to 5.17 are vulnerable to improper privilege management due to an API endpoint failing to properly limit the scope of edits, potentially leading to unauthorized modifications.
date: "2026-04-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - weblate
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
cves:
  - id: CVE-2026-34393
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34393
  - https://github.com/WeblateOrg/weblate/pull/18687
  - https://github.com/WeblateOrg/weblate/security/advisories/GHSA-3382-gw9x-477v
rules:
  - title: Weblate Suspicious User Patching API Request
    description: Detects suspicious requests to the Weblate user patching API endpoint that may indicate an attempt to exploit CVE-2026-34393.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Weblate Admin Account Creation via API
    description: Detects attempts to create admin accounts via the Weblate API, which could be indicative of exploitation following privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Weblate, a web-based localization tool, contains an improper privilege management vulnerability (CVE-2026-34393) affecting versions prior to 5.17. The vulnerability lies in the user patching API endpoint, which doesn't adequately restrict the scope of edits allowed. An attacker with low privileges could potentially exploit this flaw to modify data or settings beyond their authorized permissions. This issue was reported and patched in Weblate version 5.17. Successful exploitation can lead to data integrity issues, unauthorized access to sensitive information, and potentially, complete compromise of the Weblate instance.

## Attack Chain

1.  Attacker authenticates to Weblate with a low-privileged user account.
2.  Attacker identifies the user patching API endpoint (e.g., `/api/users/<user_id>`).
3.  Attacker crafts a malicious API request to modify attributes of a different user account, potentially an administrator.
4.  The attacker submits the request to the vulnerable API endpoint, exploiting the lack of proper scope validation.
5.  The Weblate server processes the request without correctly verifying the attacker's authorization to modify the target user's attributes.
6.  The target user's attributes are modified according to the attacker's request, potentially elevating the attacker's privileges or compromising the target user's account.
7.  The attacker leverages the elevated privileges to access sensitive data or perform unauthorized actions within the Weblate system.
8.  Attacker maintains persistent access by creating new admin accounts or backdoors within the Weblate system.

## Impact

Successful exploitation of CVE-2026-34393 can lead to significant data breaches, unauthorized modifications, and complete compromise of the Weblate instance. An attacker could gain administrative access, modify translations, and potentially inject malicious content into localized software. The number of affected installations is currently unknown, but any Weblate instance running a version prior to 5.17 is vulnerable. Organizations that rely on Weblate for their localization workflows are at risk.

## Recommendation

*   Immediately upgrade Weblate to version 5.17 or later to patch CVE-2026-34393.
*   Monitor Weblate's web server logs for suspicious API requests targeting the user patching endpoint (`/api/users/<user_id>`) as described in the Attack Chain (use the Sigma rule provided below).
*   Review user account permissions and audit logs for any unexpected privilege escalations.
*   Implement stricter input validation and authorization checks within the Weblate application to prevent similar vulnerabilities in the future.
*   Deploy the Sigma rule provided below to your SIEM to detect exploitation attempts.
