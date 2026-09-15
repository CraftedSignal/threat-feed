---
title: Authentication and Authorization Vulnerabilities in mySCADA myPRO Manager
slug: 2026-09-myscada-pro-manager
description: Multiple vulnerabilities in mySCADA myPRO Manager versions 2.1 and earlier allow unauthenticated attackers to execute arbitrary management commands or send unauthorized SMS messages.
date: "2026-09-15T16:31:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ics
  - scada
  - vulnerability
  - cve
vendors:
  - mySCADA Technologies
products:
  - mySCADA myPRO Manager (<=2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker with network access to the affected API could exploit this vulnerability to access privileged management functions.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The mySCADA myPRO Manager command API does not properly enforce authentication for privileged functions.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-03
  - https://www.cve.org/CVERecord?id=CVE-2026-73807
  - https://www.cve.org/CVERecord?id=CVE-2026-82567
  - https://www.myscada.org/downloads/mySCADAPROManager/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade mySCADA myPRO Manager to version 2.2
      owner: IT Operations
      due: 72h
      evidence: mySCADA Technologies has addressed these issues in Version 2.2
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to myPRO Manager management interfaces
      owner: Security Operations
      addresses: CVE-2026-73807
      evidence: Minimize network exposure for all control system devices
---

mySCADA Technologies has disclosed two critical vulnerabilities in its myPRO Manager software, versions 2.1 and earlier. These vulnerabilities, tracked as CVE-2026-73807 and CVE-2026-82567, expose the management API and notification gateway to unauthenticated network access. CVE-2026-73807 (CWE-862) allows an unauthenticated attacker to invoke privileged management functions within the command API. CVE-2026-82567 (CWE-306) exposes an unauthenticated HTTP endpoint in the notification gateway that permits sending arbitrary SMS messages through a connected GSM modem. These flaws affect critical infrastructure sectors including Energy, Transportation, and Water management. Defenders should prioritize updating to version 2.2 and restricting network access to these interfaces to prevent unauthorized control or messaging.

## Impact

Successful exploitation could lead to full unauthorized access to system management functions or the abuse of communication channels (GSM modems) to send unauthorized SMS messages. These vulnerabilities affect organizations across critical infrastructure sectors such as Energy, Food and Agriculture, and Water and Wastewater, posing risks to operational continuity and system integrity if accessed by malicious actors.

## Recommendation

- Upgrade mySCADA myPRO Manager to version 2.2 or later immediately to patch CVE-2026-73807 and CVE-2026-82567.
- Isolate the myPRO Manager notification gateway and command API from public internet access by placing them behind firewalls or VPNs.
- Restrict network access to the management interfaces to authorized management workstations only.
