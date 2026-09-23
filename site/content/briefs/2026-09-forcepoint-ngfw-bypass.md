---
title: Security Policy Bypass in Forcepoint Security Engine (NGFW)
slug: 2026-09-forcepoint-ngfw-bypass
description: Forcepoint has disclosed CVE-2026-12974, a security policy bypass vulnerability affecting multiple versions of the Forcepoint Security Engine (NGFW) that requires urgent administrative review and patching.
date: "2026-09-23T19:49:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:forcepoint:security_engine:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - network-security
  - patch-management
vendors:
  - Forcepoint
products:
  - Forcepoint Security Engine (NGFW) (7.1.0-7.1.13, 7.3.0-7.3.1, 7.33, 7.4.0-7.4.1, 7.5.0)
cves:
  - id: CVE-2026-12974
references:
  - https://support.forcepoint.com/s/article/Security-Advisory-Security-Policy-Bypass-in-Forcepoint-Security-Engine-NGFW-CVE-2026-12974
  - https://cyber.gc.ca/en/alerts-advisories/forcepoint-security-advisory-av26-960
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade affected Forcepoint Security Engine (NGFW) appliances to the vendor-recommended patched version.
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends applying updates.
  mitigation_plan:
    - priority: immediate
      action: Identify all instances of vulnerable Forcepoint Security Engine (NGFW) via inventory management.
      owner: IT Operations
      addresses: CVE-2026-12974
---

Forcepoint has released a security advisory concerning a critical security policy bypass vulnerability, identified as CVE-2026-12974, affecting the Forcepoint Security Engine (NGFW). The vulnerability impacts a range of software versions, specifically 7.1.0 to 7.1.13, 7.3.0 to 7.3.1, 7.33, 7.4.0 to 7.4.1, and 7.5.0. This flaw allows unauthorized modification or evasion of established network security policies enforced by the NGFW. Because the NGFW is a core component of perimeter and internal network traffic control, successful exploitation could permit attackers to bypass access controls, exfiltrate data, or facilitate lateral movement within the network. Defenders should immediately verify their NGFW version deployment and review the official Forcepoint support portal for relevant patches and remediation guidance.

## Impact

Successful exploitation of CVE-2026-12974 enables unauthorized parties to bypass security policies enforced by Forcepoint Security Engine (NGFW). If left unpatched, this vulnerability could compromise network segmentation, expose internal assets, or allow attackers to bypass traffic filtering rules, potentially leading to unauthorized data access or network infiltration.

## Recommendation

- Immediately audit your environment for the affected Forcepoint Security Engine (NGFW) versions listed in this brief.
- Review the official Forcepoint Security Advisory (CVE-2026-12974) via the Forcepoint Support Hub for available firmware updates and specific configuration workarounds.
- Prioritize patching for internet-facing NGFW deployments that enforce critical perimeter security policies.
- Monitor NGFW administrative logs for unauthorized or unexpected policy changes that may indicate exploitation attempts.
