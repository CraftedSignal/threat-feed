---
title: Authentication Bypass in Fleet Device API
slug: 2026-10-fleet-auth-bypass
description: Fleet versions before 4.87.0 contain an authentication bypass vulnerability in the device API that allows unauthenticated attackers to spoof iOS or iPadOS devices using predictable identifiers.
date: "2026-10-01T12:41:31Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:fleetdm:fleet:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-103264
  - mdm
vendors:
  - FleetDM
products:
  - Fleet (< 4.87.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Fleet versions before 4.87.0 contain an authentication bypass vulnerability in the device API.
    confidence_band: high
cves:
  - id: CVE-2026-103264
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103264
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Fleet to version 4.87.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source notes vulnerability exists in versions before 4.87.0
  mitigation_plan:
    - priority: immediate
      action: Patch Fleet software to 4.87.0
      owner: IT Operations
      addresses: CVE-2026-103264
      evidence: NVD vulnerability disclosure
---

Fleet versions prior to 4.87.0 are affected by an authentication bypass vulnerability located in the device API. The application improperly accepts hostnames or hardware serial numbers as valid authentication tokens in addition to the required device UUIDs. Because hostnames and serial numbers are often discoverable or guessable, an unauthenticated attacker can effectively spoof a legitimate iOS or iPadOS host. Successful exploitation allows the attacker to authenticate as a registered device, facilitating unauthorized access to sensitive device data. Furthermore, the attacker can influence device-scoped operations, such as triggering unauthorized software installations or migrating device management (MDM) configurations, posing a significant risk to fleet integrity and security posture.

## Impact

Successful exploitation of this vulnerability permits unauthorized access to sensitive device information and enables the execution of administrative actions across the fleet. Attackers may conduct unauthorized software deployments or move devices to malicious MDM environments, potentially leading to total loss of control over affected endpoints.

## Recommendation

* Upgrade all instances of Fleet to version 4.87.0 or later to remediate the authentication bypass vulnerability in the device API (CVE-2026-103264).
* Review access logs for the device API to identify unexpected authentication attempts originating from anomalous sources or those using non-UUID tokens if logging granularity permits.
