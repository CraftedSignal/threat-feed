---
title: ChurchCRM Authenticated API User Authorization Bypass (CVE-2026-39331)
slug: 2026-04-churchcrm-auth-bypass
description: An authenticated API user of ChurchCRM prior to v7.1.0 can bypass authorization checks and modify arbitrary family records by manipulating the familyId parameter in API requests, leading to privilege escalation and potential data manipulation.
date: "2026-04-07T18:16:44Z"
severities:
  - high
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

ChurchCRM is an open-source church management system. Prior to version 7.1.0, a critical vulnerability exists (CVE-2026-39331) that allows authenticated API users to bypass authorization controls and modify family records without proper privileges. This is achieved by manipulating the `{familyId}` parameter in specific API requests. The vulnerability lies in the absence of role-based access control on several key API endpoints, including `/family/{familyId}/verify`…
