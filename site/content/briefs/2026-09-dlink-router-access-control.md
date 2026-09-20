---
title: Improper Access Control Vulnerability in D-Link DIR-X1860 Routers
slug: 2026-09-dlink-router-access-control
description: D-Link DIR-X1860 and DIR-X1860Z routers are vulnerable to improper access control via the /ubus component in the routerd service, enabling local network attackers to exploit the passwd_set argument.
date: "2026-09-20T16:22:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:h:dlink:dir-x1860:*:*:*:*:*:*:*:*
  - cpe:2.3:h:dlink:dir-x1860z:*:*:*:*:*:*:*:*
vendors:
  - D-Link
products:
  - DIR-X1860 (<= 1.0.2.220120.165402)
  - DIR-X1860Z (<= 1.0.2.220120.165402)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The manipulation of the argument passwd_set results in improper access controls.
    confidence_band: high
cves:
  - id: CVE-2026-94036
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94036
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all D-Link DIR-X1860 and DIR-X1860Z devices
      owner: IT Operations
      due: 24h
      evidence: Affected products list
  mitigation_plan:
    - priority: immediate
      action: Update firmware to the latest available version beyond 1.0.2.220120.165402
      owner: IT Operations
      addresses: CVE-2026-94036
      evidence: NVD vulnerability disclosure
---

A security vulnerability identified as CVE-2026-94036 affects D-Link DIR-X1860 and DIR-X1860Z router models running firmware versions up to 1.0.2.220120.165402. The flaw exists within the 'routerd' service, specifically in the handling of the '/ubus' component. An attacker positioned on the local network can manipulate the 'passwd_set' argument to bypass existing access controls. This vulnerability poses a significant risk to home and small office environments, as a publicly available exploit has been released, allowing potential unauthorized access or configuration changes to the affected networking hardware. Defenders should prioritize updating firmware where available or isolating vulnerable devices from untrusted local network segments.

## Impact

Successful exploitation of CVE-2026-94036 allows an attacker on the local network to gain unauthorized access or manipulate security controls on affected D-Link routers. This could lead to a complete compromise of the network gateway, enabling traffic interception, unauthorized configuration modifications, or the redirection of user traffic.

## Recommendation

- Identify all D-Link DIR-X1860 and DIR-X1860Z devices in the environment using asset management logs.
- Patch affected devices to the latest firmware version released by D-Link beyond 1.0.2.220120.165402.
- If a patch is unavailable, restrict management interface access by placing vulnerable routers behind a segmented VLAN or firewall to ensure they are not accessible to unauthorized local network entities.
