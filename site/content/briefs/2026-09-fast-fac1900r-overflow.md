---
title: Critical Buffer Overflow in FAST FAC1900R devdiscover Service
slug: 2026-09-fast-fac1900r-overflow
description: A critical stack-based buffer overflow in the devdiscover service of the FAST FAC1900R network device allows remote code execution due to improper handling in the copy_msg_element function.
date: "2026-09-28T12:14:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:fast:fac1900r:*:*:*:*:*:*:*:*
vendors:
  - FAST
products:
  - FAC1900R (20190827_2.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-101039
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101039
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Network Engineering
  immediate_actions:
    - action: Restrict network access to FAST FAC1900R management and discovery ports
      owner: Network Engineering
      due: 24h
      evidence: CVE-2026-101039 stack-based buffer overflow
  mitigation_plan:
    - priority: immediate
      action: Isolate affected devices from the internet
      owner: Network Engineering
      addresses: CVE-2026-101039
      evidence: Remotely exploitable buffer overflow
---

A critical security vulnerability (CVE-2026-101039) has been identified in the FAST FAC1900R device, specifically firmware version 20190827_2.0.2. The vulnerability exists within the copy_msg_element function of the devdiscover service, which is responsible for network device discovery. This flaw allows a remote, unauthenticated attacker to trigger a stack-based buffer overflow by sending specially crafted packets to the affected service. Successful exploitation of this vulnerability can lead to arbitrary code execution on the device or cause a denial of service (DoS) condition. As the vendor has not responded to disclosure efforts and public exploit code is available, this vulnerability poses a significant risk to organizations utilizing this hardware in their network infrastructure.

## Impact

Successful exploitation allows remote attackers to compromise the integrity and availability of FAST FAC1900R network devices. Attackers can gain remote code execution to establish persistence, move laterally within the network, or disrupt critical network services managed by the device. As of this report, no vendor patch is available.

## Recommendation

Prioritize the isolation of all FAST FAC1900R devices from the public internet. Ensure these devices are positioned behind strict firewall rules that restrict access to the devdiscover service ports to trusted management subnets only. Given the unavailability of a vendor patch, decommissioning these legacy devices is the recommended path for risk mitigation in sensitive environments.
