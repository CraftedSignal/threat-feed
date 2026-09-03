---
title: Memory Exhaustion Vulnerability in MOOS-IvP pMarineViewer
slug: 2026-09-moos-ivp-memory-exhaustion
description: An unauthenticated memory exhaustion vulnerability in MOOS-IvP pMarineViewer (<= 24.8.1) allows attackers to stall the operator display by flooding the application with unbounded NODE_REPORT messages.
date: "2026-09-03T23:29:10Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:moos_ivp:pmarineviewer:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - marine-systems
vendors:
  - MOOS-IvP
products:
  - pMarineViewer (<= 24.8.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can publish crafted NODE_REPORT data to cause memory exhaustion and stall the operator display without authentication.
    confidence_band: high
cves:
  - id: CVE-2026-85449
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85449
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all systems running pMarineViewer and confirm versioning.
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability affects pMarineViewer <= 24.8.1
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the MOOS communication bus to trusted entities only.
      owner: Security Operations
      addresses: CVE-2026-85449
      evidence: Vulnerability allows unauthenticated injection into the communication bus
---

MOOS-IvP pMarineViewer, an application typically used for marine autonomy and visualization, contains a vulnerability in how it handles NODE_REPORT messages. The application fails to enforce limits on the number of tracked node identities processed by the system. An attacker with access to the MOOS publish/subscribe communication bus can inject a large volume of crafted NODE_REPORT messages, each containing a unique node name. This action forces the application to allocate memory for every distinct identity reported. Continued injection leads to significant memory exhaustion, eventually causing the operator display to stall or crash. This issue is particularly critical in systems where pMarineViewer is used for mission-critical situational awareness. The vulnerability affects all versions up to and including 24.8.1.

## Impact

Successful exploitation results in a denial-of-service condition for the pMarineViewer operator display. In the context of marine robotic missions, this prevents operators from receiving real-time situational awareness, potentially leading to the loss of control or monitoring of autonomous assets. The vulnerability is unauthenticated and impacts the core visualization utility of the MOOS-IvP software suite.

## Recommendation

Prioritized actions for security teams:
- Inventory systems running MOOS-IvP and identify instances of pMarineViewer version 24.8.1 or earlier.
- Implement network-level or middleware access controls to restrict access to the MOOS publish/subscribe communication bus, preventing unauthorized entities from injecting arbitrary NODE_REPORT messages.
- Prioritize the deployment of updates provided by the MOOS-IvP maintainers that implement validation and limiting logic on node identity tracking.
