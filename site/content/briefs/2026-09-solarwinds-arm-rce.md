---
title: Unauthenticated Remote Code Execution in SolarWinds Access Rights Manager
slug: 2026-09-solarwinds-arm-rce
description: CVE-2026-28326 is a critical remote code execution vulnerability in SolarWinds Access Rights Manager resulting from the use of a hardcoded static key, allowing unauthenticated attackers to execute arbitrary code.
date: "2026-09-17T17:59:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:solarwinds:access_rights_manager:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - windows
vendors:
  - SolarWinds
products:
  - Access Rights Manager
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The issue stems from a hardcoded static key, which allows unauthenticated attackers to execute arbitrary code on the target system.
    confidence_band: high
cves:
  - id: CVE-2026-28326
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28326
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all instances of SolarWinds Access Rights Manager and verify current version.
      owner: IT Operations
      due: 24h
      evidence: Identification of affected software instance.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied security patches to remediate CVE-2026-28326.
      owner: IT Operations
      addresses: CVE-2026-28326
      evidence: Vendor patch availability is standard remediation for RCE.
---

SolarWinds Access Rights Manager is affected by a critical remote code execution vulnerability, tracked as CVE-2026-28326. The vulnerability arises from the implementation of a hardcoded static cryptographic key within the application. This flaw enables an unauthenticated attacker to bypass authentication mechanisms and execute arbitrary code on the underlying host. Given that Access Rights Manager typically operates with high-privileged service accounts to manage directory and file permissions across an organization, successful exploitation poses a severe risk of full environment compromise. Organizations utilizing SolarWinds Access Rights Manager on Windows Server platforms are urged to review security advisories from SolarWinds for patch availability and mitigation guidance, as this vulnerability provides a direct pathway for initial access and execution without requiring valid credentials.

## Impact

Successful exploitation allows unauthenticated attackers to achieve remote code execution on the target Windows Server hosting the Access Rights Manager software. Because the application manages sensitive access controls, compromised instances could lead to unauthorized privilege escalation, exfiltration of directory services data, and persistent access across the enterprise network.

## Recommendation

Prioritize the identification of all internet-facing or internal SolarWinds Access Rights Manager instances. Monitor for security updates provided by SolarWinds and apply patches as soon as they are released. Ensure that service accounts utilized by Access Rights Manager follow the principle of least privilege to contain potential blast radiuses.
