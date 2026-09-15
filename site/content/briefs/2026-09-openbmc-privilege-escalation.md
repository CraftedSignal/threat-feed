---
title: Privilege Escalation Vulnerability in OpenBMC phosphor-net-ipmid (CVE-2026-16140)
slug: 2026-09-openbmc-privilege-escalation
description: A logic flaw in OpenBMC's phosphor-net-ipmid implementation allows authenticated remote attackers to hijack existing sessions and perform unauthorized privilege escalation.
date: "2026-09-15T15:31:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - ipmi
  - openbmc
vendors:
  - OpenBMC
  - NVIDIA
  - H3C
products:
  - phosphor-net-ipmid
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This issue effectively allows for privilege escalation without re-authentication.
    confidence_band: high
cves:
  - id: CVE-2026-16140
    cvss: 8.8
references:
  - https://www.runzero.com/advisories/openbmc-ipmi-privsec-rakp-cve-2026-16140/
  - https://www.runzero.com/blog/lights-out-exposed/
  - https://sploitus.com/exploit?id=CVE-2026-16140
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all servers running OpenBMC based firmware and confirm patch status against vendor updates.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-16140 vulnerability
  mitigation_plan:
    - priority: immediate
      action: Apply firmware updates from hardware vendors once available.
      owner: IT Operations
      addresses: CVE-2026-16140
      evidence: RunZero advisory regarding phosphor-net-ipmid logic flaw
---

OpenBMC's IPMI implementation, phosphor-net-ipmid, is vulnerable to a critical logic flaw (CVE-2026-16140) in its Remote Authentication and Key Exchange (RAKP) mechanism. An attacker who has already established a low-privilege session can trigger this vulnerability to replace their current authorization context with that of a target account, such as an administrator, without requiring re-authentication. The vulnerability persists because the session maintains the original integrity and encryption keys even after the authorization context is swapped. This flaw poses a significant risk to data center infrastructure, as OpenBMC is widely utilized in server management stacks by various vendors, including NVIDIA and H3C. Given the availability of public proof-of-concept exploit code, administrators should prioritize identifying and patching impacted BMC firmware.

## Impact

Successful exploitation of CVE-2026-16140 allows an attacker to achieve full unauthorized control over the baseboard management controller (BMC), leading to complete loss of confidentiality, integrity, and availability of the managed server hardware. This vulnerability affects downstream vendors integrating OpenBMC, impacting enterprise, cloud, and high-performance computing environments where IPMI is exposed to the management network.

## Recommendation

- Identify all servers running OpenBMC-based firmware within your environment using internal asset management or vulnerability scanning tools.
- Review the advisories from your specific hardware vendors (such as NVIDIA or H3C) for firmware updates that address CVE-2026-16140.
- Apply the vendor-provided firmware patches to all vulnerable BMCs immediately.
- Restrict access to the IPMI/BMC management network to authorized management subnets and jump hosts to limit exposure.
