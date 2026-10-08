---
title: Weak Password Recovery Mechanism in MyRezzta
slug: 2026-10-myrezzta-vuln
description: CVE-2026-19218 in AKIN Software MyRezzta versions 2.06.03 through 2.07.00 allows unauthorized account access via a flawed password recovery mechanism.
date: "2026-10-08T15:09:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:akinsoftware:myrezzta:2.06.03:*:*:*:*:*:*:*
  - cpe:2.3:a:akinsoftware:myrezzta:2.07.00:*:*:*:*:*:*:*
vendors:
  - AKIN Software
products:
  - MyRezzta (2.06.03 - 2.07.00)
cves:
  - id: CVE-2026-19218
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19218
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade MyRezzta to version 2.07.01 or later
      owner: IT Operations
      addresses: CVE-2026-19218
      evidence: NVD vulnerability disclosure confirms patch availability in 2.07.01
---

AKIN Software has disclosed a critical vulnerability, tracked as CVE-2026-19218, within the MyRezzta application. This flaw resides in the password recovery mechanism and allows an unauthenticated attacker to manipulate the recovery process to gain unauthorized access to user accounts. The vulnerability affects versions 2.06.03 through 2.07.00. Given the high CVSS base score of 9.1, this represents a significant risk to organizations utilizing MyRezzta for account management. Defenders should prioritize identifying instances of this software within their environment and verifying the version to ensure a move to a patched state is possible or, if no patch exists, implementing compensatory controls around the recovery flow.

## Impact

The vulnerability poses a severe risk of account takeover. If successfully exploited, an attacker can compromise legitimate user accounts without requiring original credentials, potentially leading to data exfiltration, unauthorized administrative actions, or lateral movement within the application environment. The scope of impact is limited to organizations currently running versions 2.06.03 to 2.07.00 of MyRezzta.

## Recommendation

- Identify all instances of MyRezzta within the network environment by monitoring for relevant process names or registry entries associated with the application installation.
- Upgrade MyRezzta to version 2.07.01 or later immediately, as this version contains the fix for the password recovery flaw.
- Until the software is updated, implement heightened monitoring for password reset requests or access logs associated with the MyRezzta web interface to detect anomalous account recovery activity.
