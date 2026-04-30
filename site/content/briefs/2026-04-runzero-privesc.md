---
title: runZero Platform Superuser Privilege Escalation (CVE-2026-5373)
slug: 2026-04-runzero-privesc
description: CVE-2026-5373 is an improper privilege management vulnerability in the runZero platform that allows all-organization administrators to promote accounts to superuser status, which was fixed in version 4.0.260202.0.
date: "2026-04-07T15:17:47Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - cve
  - runzero
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5373
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5373
  - https://help.runzero.com/docs/release-notes/#402602020
  - https://www.runzero.com/advisories/runzero-platform-su-privesc-cve-2026-5373/
iocs:
  - type: url
    value: https://help.runzero.com/docs/release-notes/#402602020
  - type: url
    value: https://www.runzero.com/advisories/runzero-platform-su-privesc-cve-2026-5373/
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect runZero Superuser Privilege Escalation Attempt
    description: Detects attempts to exploit CVE-2026-5373 by monitoring for unexpected user role changes in runZero platform logs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect runZero Admin API Access
    description: Detects access to runZero admin APIs, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5373 is an improper privilege management vulnerability affecting the runZero platform. This vulnerability allows administrators with "all-organization" privileges to escalate the privileges of other accounts to superuser status. This could allow a malicious or compromised administrator account to gain complete control over the runZero platform instance. The vulnerability is classified as CWE-269 (Improper Privilege Management) and has a CVSS v3.1 score of 8.1 (High). The vulnerability was patched in runZero Platform version 4.0.260202.0. This issue allows an attacker with admin access to gain complete control over the platform.

## Attack Chain

1. An attacker gains administrative access to a runZero platform instance with "all-organization" privileges. This could be achieved through compromised credentials or other means.
2. The attacker navigates to the user management section of the runZero platform.
3. The attacker selects a target user account.
4. The attacker uses the "promote to superuser" functionality, which due to the vulnerability, does not have proper validation.
5. The runZero platform incorrectly elevates the target user's privileges to superuser.
6. The attacker logs in as the newly promoted superuser account.
7. The attacker now has full control over the runZero platform, including access to sensitive data and the ability to modify system configurations.

## Impact

Successful exploitation of CVE-2026-5373 allows an attacker with compromised administrator credentials to escalate privileges to superuser, gaining complete control over the runZero platform. This could lead to the exposure of sensitive asset data, the modification of network configurations, and potentially the compromise of other systems connected to the runZero platform. The exact number of affected organizations is unknown, but all installations prior to version 4.0.260202.0 are potentially vulnerable.

## Recommendation

*   Upgrade all runZero platform instances to version 4.0.260202.0 or later to patch CVE-2026-5373.
*   Monitor runZero platform logs for any unusual activity related to user privilege changes. Enable process creation logging to detect unusual activity.
*   Implement multi-factor authentication for all runZero administrator accounts to reduce the risk of credential compromise.
*   Deploy the Sigma rule to detect potential exploitation attempts by monitoring for unexpected user role changes.
*   Review and restrict administrator privileges according to the principle of least privilege.
