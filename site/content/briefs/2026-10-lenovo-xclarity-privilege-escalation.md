---
title: Lenovo XClarity Controller 3 Privilege Escalation Vulnerability
slug: 2026-10-lenovo-xclarity-privilege-escalation
description: A vulnerability in Lenovo XClarity Controller 3 allows a remote, unauthenticated attacker to gain administrative privileges on the affected system, representing a significant security risk for managed infrastructure.
date: "2026-10-14T22:21:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lenovo:xclarity_controller_3:*:*:*:*:*:*:*:*
  - cpe:2.3:a:mobyproject:buildkit:*:*:*:*:*:*:*:*
vendors:
  - Lenovo
products:
  - XClarity Controller 3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in Lenovo XClarity Controller 3 allows a remote, unauthenticated attacker to gain administrative privileges on the affected system.
    confidence_band: high
cves:
  - id: CVE-2024-23651
    cvss: 8.7
    epss: 0.00911
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3902
  - https://nvd.nist.gov/vuln/detail/CVE-2024-23651
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Lenovo XClarity Controller 3 firmware to address CVE-2024-23651.
      owner: IT Operations
      due: 72h
      evidence: Advisory identifies vulnerability requiring firmware update.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to XClarity Controller management interfaces to trusted management networks only.
      owner: IT Operations
      addresses: CVE-2024-23651
      evidence: Vulnerability allows remote exploitation, necessitating network boundary enforcement.
---

Lenovo XClarity Controller 3 (XCC3) contains a security vulnerability identified as CVE-2024-23651. This flaw allows a remote, unauthenticated attacker to interact with the management controller and elevate their privileges to the administrative level. Because XClarity controllers provide low-level management capabilities for server hardware, gaining administrative access grants an attacker complete control over the host server, including the ability to modify firmware, reconfigure system settings, or intercept data flowing through the hardware. Defenders should prioritize updating affected controller firmware to mitigate the risk of unauthorized administrative access.

## Impact

Successful exploitation of this vulnerability enables unauthenticated remote attackers to obtain administrative control over Lenovo server infrastructure. This impact level includes potential for persistent hardware-level compromise, exfiltration of sensitive configuration data, and full disruption of server availability. Organizations relying on Lenovo infrastructure for core business operations are at risk of significant downtime and data compromise if these systems are exposed to untrusted networks.

## Recommendation

* Apply the firmware updates provided by Lenovo to address CVE-2024-23651 on all affected XClarity Controller 3 systems immediately.
* Ensure management interfaces are not exposed to the public internet and are restricted to isolated management networks accessed via hardened jump hosts.
* Audit logs for unauthorized sessions or administrative account changes originating from unexpected IP addresses targeting the XCC3 management interface.
