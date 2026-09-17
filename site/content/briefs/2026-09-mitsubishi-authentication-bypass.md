---
title: Authentication Bypass Vulnerability in Mitsubishi Electric GX Works3
slug: 2026-09-mitsubishi-authentication-bypass
description: An incorrect implementation of the authentication algorithm (CVE-2026-15688) in Mitsubishi Electric GX Works3 and Motion Control Settings allows local attackers to bypass block password protections and manipulate control programs.
date: "2026-09-17T17:11:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mitsubishielectric:gx_works3:*:*:*:*:*:*:*:*
tags:
  - industrial-control-systems
  - cve
  - authentication-bypass
vendors:
  - Mitsubishi Electric
products:
  - GX Works3 (all versions)
  - Motion Control Settings (all versions)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Incorrect Implementation of Authentication Algorithm (CWE-303) vulnerability in the affected products allows a local attacker to successfully authenticate even with an invalid block password.
    confidence_band: high
cves:
  - id: CVE-2026-15688
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-02
  - https://www.cve.org/CVERecord?id=CVE-2026-15688
  - https://www.mitsubishielectric.com/psirt/vulnerability/pdf/2026-007_en.pdf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade GX Works3 to 1.096A and Motion Control Settings to 1.070Y
      owner: IT Operations
      due: 72h
      evidence: Vendor remediation instructions in advisory 2026-007
  mitigation_plan:
    - priority: immediate
      action: Set project security version to '2' after patching
      owner: OT Security
      addresses: CVE-2026-15688
      evidence: Vendor recommendation in 2026-007
---

Mitsubishi Electric GX Works3 and the bundled Motion Control Settings software are affected by an authentication algorithm flaw (CVE-2026-15688), classified as CWE-303. This vulnerability stems from an incorrect implementation that allows a local user to bypass security controls. By executing the application and performing memory manipulation to alter parts of the loaded executable module, an attacker can circumvent password validation mechanisms. Successful exploitation grants the attacker the ability to view, tamper with, destroy, or delete critical control programs used in industrial manufacturing environments. Given the potential impact on control logic, the vulnerability is highly critical in operational technology (OT) settings where integrity of control programs is essential for safety and uptime.

## Impact

The vulnerability affects users of Mitsubishi Electric GX Works3 and Motion Control Settings worldwide, particularly within the critical manufacturing sector. Successful exploitation leads to total loss of integrity and availability of control programs, potentially resulting in unauthorized process modification or operational disruption. The vulnerability is assigned a CVSS v3.1 score of 8.8 (High) and a CVSS v4.0 score of 9.2 (Critical).

## Recommendation

* Update Mitsubishi Electric GX Works3 to version 1.096A or later to address CVE-2026-15688.
* Update Motion Control Settings to version 1.070Y or later.
* Following the update, configure the security version for projects to "2" as detailed in the Mitsubishi Electric security manual.
* Restrict local physical access to workstations running the affected software and implement rigorous access controls for all users who interact with these machines.
* Deploy endpoint security solutions to monitor for suspicious process injection or memory modification attempts on engineering workstations.
* Isolate control system networks from untrusted networks and the internet, ensuring remote access is restricted to authenticated, VPN-secured connections.
