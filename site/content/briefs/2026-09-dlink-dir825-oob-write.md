---
title: Remote Out-of-Bounds Write in D-Link DIR-825
slug: 2026-09-dlink-dir825-oob-write
description: A critical out-of-bounds write vulnerability in the D-Link DIR-825 firmware (version 3.00b32) allows remote attackers to trigger memory corruption via the peer_hostname parameter.
date: "2026-09-24T04:45:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:dlink:dir-825:3.00b32:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve
  - network-security
vendors:
  - D-Link
products:
  - DIR-825 (3.00b32)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-96891
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96891
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Isolate D-Link DIR-825 devices running version 3.00b32 from internet-facing segments
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-96891 is remotely exploitable
  mitigation_plan:
    - priority: immediate
      action: Apply firmware update for DIR-825 when provided by D-Link
      owner: IT Operations
      addresses: CVE-2026-96891
      evidence: Official NVD vulnerability report
---

CVE-2026-96891 is a critical security vulnerability discovered in the D-Link DIR-825 router, specifically affecting firmware version 3.00b32. The flaw resides within the tunnel_set_params function located in the rp-l2tp component, specifically within the source file tunnel.c. An attacker can trigger the vulnerability by sending a maliciously crafted input to the peer_hostname argument. Because the input handling fails to properly validate memory boundaries, this manipulation results in an out-of-bounds write condition. This flaw is remotely exploitable, posing a significant risk to affected devices by potentially allowing unauthenticated remote code execution or causing persistent denial-of-service conditions through device instability and memory corruption.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.8, indicating a high potential for severe impact. Successful exploitation allows remote attackers to compromise the integrity and availability of the affected D-Link DIR-825 hardware. This may lead to total device takeover or system crashes, impacting network availability for organizations or home users relying on this router.

## Recommendation

1. Identify all D-Link DIR-825 devices running firmware version 3.00b32 within the organization's network inventory.
2. Restrict management interface access for identified devices to trusted administrative subnets until a vendor patch is applied.
3. Monitor ingress traffic to the device for unusual strings or payload patterns targeting L2TP configurations that might indicate exploitation attempts.
4. Contact D-Link support or check the official product security portal for firmware updates resolving CVE-2026-96891.
