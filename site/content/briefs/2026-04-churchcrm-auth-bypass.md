---
title: ChurchCRM Authenticated API User Authorization Bypass (CVE-2026-39331)
slug: 2026-04-churchcrm-auth-bypass
description: An authenticated API user of ChurchCRM prior to v7.1.0 can bypass authorization checks and modify arbitrary family records by manipulating the familyId parameter in API requests, leading to privilege escalation and potential data manipulation.
date: "2026-04-07T18:16:44Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-39331
  - churchcrm
  - authorization-bypass
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-39331
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39331
rules:
  - title: ChurchCRM Family ID Manipulation
    description: Detects potential attempts to exploit CVE-2026-39331 by monitoring requests to vulnerable ChurchCRM API endpoints with unusual Family IDs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: ChurchCRM Family Deactivation Attempt
    description: Detects potential attempts to exploit CVE-2026-39331 by monitoring requests to deactivate a family via the /family/{familyId}/activate/{status} endpoint.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ChurchCRM is an open-source church management system. Prior to version 7.1.0, a critical vulnerability exists (CVE-2026-39331) that allows authenticated API users to bypass authorization controls and modify family records without proper privileges. This is achieved by manipulating the `{familyId}` parameter in specific API requests. The vulnerability lies in the absence of role-based access control on several key API endpoints, including `/family/{familyId}/verify`, `/family/{familyId}/verify/url`, `/family/{familyId}/verify/now`, `/family/{familyId}/activate/{status}`, and `/family/{familyId}/geocode`. This allows attackers to deactivate/reactivate families, spam verification emails, mark families as verified, and trigger geocoding actions without the necessary permissions. This vulnerability poses a significant risk to the integrity and availability of ChurchCRM data, especially in multi-tenant environments. Upgrade to version 7.1.0 to remediate this vulnerability.

## Attack Chain

1. An attacker authenticates to the ChurchCRM API with valid user credentials.
2. The attacker identifies a target `familyId` that they do not have explicit modification rights for.
3. The attacker crafts a malicious API request to one of the vulnerable endpoints: `/family/{familyId}/verify`, `/family/{familyId}/verify/url`, `/family/{familyId}/verify/now`, `/family/{familyId}/activate/{status}`, or `/family/{familyId}/geocode`.
4. The attacker replaces the `{familyId}` parameter in the request URL with the target `familyId`.
5. For example, the attacker sends a POST request to `/family/123/activate/false` to deactivate family with ID 123.
6. Due to the lack of role-based access control, the server processes the request without verifying if the attacker has the necessary `EditRecords` privilege.
7. The target family's state is modified (e.g., deactivated, marked as verified).
8. The attacker repeats this process for other families and actions, potentially causing widespread disruption or data manipulation.

## Impact

Successful exploitation of CVE-2026-39331 allows an attacker to escalate privileges and manipulate sensitive family data within ChurchCRM. This can lead to unauthorized deactivation of families, generation of spam verification emails, inaccurate family verification status, and resource exhaustion due to excessive geocoding requests. While specific victim counts are unknown, all ChurchCRM instances prior to version 7.1.0 are vulnerable. The consequences include reputational damage, data integrity issues, and potential disruption of church operations.

## Recommendation

*   Immediately upgrade ChurchCRM to version 7.1.0 to patch CVE-2026-39331 and address the authorization bypass vulnerability.
*   Monitor web server logs for suspicious requests to the vulnerable API endpoints (`/family/{familyId}/verify`, `/family/{familyId}/verify/url`, `/family/{familyId}/verify/now`, `/family/{familyId}/activate/{status}`, `/family/{familyId}/geocode`) as detected by the Sigma rule "ChurchCRM Family ID Manipulation".
*   Implement stricter input validation and role-based access controls on all API endpoints to prevent unauthorized data modification, especially those handling sensitive data like family records.
*   Review and audit existing ChurchCRM user permissions to identify and revoke any unnecessary privileges that could be exploited in conjunction with this vulnerability.
