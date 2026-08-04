---
title: Missing Authorization Vulnerability in HAVELSAN Liman MYS
slug: 2026-08-liman-mys-privesc
description: A missing authorization vulnerability (CVE-2026-18650) in HAVELSAN Liman MYS versions 2.2.3 through 2.3.0 allows authenticated users to escalate privileges.
date: "2026-08-04T15:44:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - havelsan
vendors:
  - HAVELSAN Inc.
products:
  - Liman MYS
cves:
  - id: CVE-2026-18650
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18650
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0741
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Liman MYS to version 2.3.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-18650 vulnerability remediation requires upgrade
  mitigation_plan:
    - priority: immediate
      action: Upgrade software
      owner: IT Operations
      addresses: CVE-2026-18650
---

HAVELSAN Inc. Liman MYS versions 2.2.3 through 2.3.0 contain a vulnerability (CVE-2026-18650) classified as a Missing Authorization flaw (CWE-862). This vulnerability, reported by the Computer Emergency Response Team of the Republic of Turkey, allows an authenticated user to perform actions that should be restricted to higher-privileged accounts. The flaw carries a CVSS v3.1 base score of 8.8, indicating a high risk of complete system compromise, including unauthorized access to sensitive data and system impact. Organizations using Liman MYS are advised to update to version 2.3.1 or later to remediate the authorization check deficiency.

## Attack Chain

1. Attacker obtains valid low-privileged credentials for the Liman MYS instance.
2. Attacker interacts with the web interface of the target system.
3. Attacker identifies administrative endpoints or API functions that lack server-side authorization checks.
4. Attacker crafts requests to these endpoints, bypassing the UI-level restrictions.
5. The application processes the request due to the missing authorization validation.
6. Attacker gains elevated permissions or executes unauthorized actions within the system context.
7. Final objective: Complete administrative control of the Liman MYS management interface.

## Impact

Successful exploitation allows an attacker to escalate privileges within the Liman MYS environment, potentially resulting in unauthorized administrative access, data exfiltration, or modification of system configurations. This vulnerability impacts all installations of Liman MYS running versions 2.2.3 to 2.3.0, representing a significant risk to organizations managing their infrastructure via this platform.

## Recommendation

* Apply the update to Liman MYS version 2.3.1 or later immediately to patch CVE-2026-18650.
* Audit access logs for unauthorized attempts to access administrative URL endpoints by low-privileged user accounts.
* Enforce strict least-privilege access for all users authenticated to the Liman MYS dashboard.
