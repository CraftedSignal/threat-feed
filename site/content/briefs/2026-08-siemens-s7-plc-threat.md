---
title: Active Exploitation of Siemens S7 Series PLCs in US Critical Infrastructure
slug: 2026-08-siemens-s7-plc-threat
description: The IC3 has issued an advisory regarding the active exploitation of Siemens S7 Series PLCs within US critical infrastructure sectors using CVE-2026-4357 to disrupt operational technology.
date: "2026-08-26T05:08:22Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - critical-infrastructure
  - ot-security
  - vulnerability-management
vendors:
  - Siemens
products:
  - S7 Series PLC
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The IC3 has issued an alert regarding active targeting of Siemens S7 Series programmable logic controllers (PLCs) within critical infrastructure sectors in the United States.
    confidence_band: high
references:
  - https://www.ic3.gov/CSA/2026/260819.pdf
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - OT Security Operations
  immediate_actions:
    - action: Isolate internet-exposed Siemens S7 PLCs
      owner: OT Security Operations
      due: 24h
      evidence: IC3 Industry Alert active threat notice
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2026-4357
      owner: OT Engineering
      addresses: CVE-2026-4357
      evidence: IC3 Industry Alert CVE identification
---

The FBI's Internet Crime Complaint Center (IC3) has identified a campaign targeting Siemens S7 Series programmable logic controllers (PLCs) deployed across critical infrastructure sectors in the United States. Threat actors are actively exploiting a high-severity vulnerability, tracked as CVE-2026-4357, to gain unauthorized access to industrial control systems. This activity represents a significant risk to operational technology (OT) environments, as successful exploitation allows adversaries to manipulate industrial processes, potentially leading to physical disruption or equipment damage. Defenders in industrial and critical infrastructure environments must prioritize the assessment of S7 PLC exposure to the internet and ensure that the patches addressing CVE-2026-4357 are applied in accordance with vendor guidance.

## Impact

The campaign poses a direct threat to the availability and safety of industrial operations. Successful exploitation enables unauthorized control over critical infrastructure components, which could result in operational outages, process manipulation, or long-term damage to OT assets. Targeted sectors include energy, water, and manufacturing, where uptime and system integrity are paramount for public safety and operational continuity.

## Recommendation

* Identify and isolate all Siemens S7 Series PLCs currently exposed to the public internet to mitigate immediate risks.
* Audit industrial control network perimeters and block unauthorized traffic directed at common PLC communication ports, specifically focusing on the industrial protocols used by S7 devices.
* Apply security patches provided by Siemens to remediate CVE-2026-4357 across all affected S7 Series PLC deployments.
* Enhance monitoring of network traffic between business-critical IT networks and OT enclaves to detect lateral movement or anomalous protocol activity.
