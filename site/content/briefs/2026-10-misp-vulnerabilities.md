---
title: Multiple Vulnerabilities in MISP
slug: 2026-10-misp-vulnerabilities
description: Multiple vulnerabilities in MISP allow a remote, authenticated attacker to perform privilege escalation to Site Administrator, bypass security controls, manipulate data, or execute cross-site scripting attacks.
date: "2026-10-01T14:14:46Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - MISP Project
products:
  - MISP
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein entfernter, authentisierter Angreifer kann mehrere Schwachstellen in MISP ausnutzen, um seine Berechtigungen bis auf Site-Administrator-Ebene zu erweitern.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Sicherheitsmaßnahmen zu umgehen
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
    evidence: Daten zu manipulieren oder offenzulegen
    confidence_band: med
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3689
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all production MISP instances to the latest release.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends security hardening against reported vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Patch MISP to the latest stable version.
      owner: IT Operations
      addresses: Multiple undisclosed MISP vulnerabilities
      evidence: Source advisory
---

The MISP Project has disclosed multiple vulnerabilities affecting MISP (Malware Information Sharing Platform). These flaws allow a remote, authenticated attacker to escalate privileges to the level of a Site Administrator, bypass existing security controls, perform unauthorized data manipulation, disclose sensitive information, or carry out stored and reflected Cross-Site Scripting (XSS) attacks. Given that MISP is frequently used to store highly sensitive threat intelligence, the potential impact of an account takeover or administrative compromise is significant, potentially granting an adversary visibility into an organization's entire threat research and response lifecycle. Defenders should review MISP instance logs for unusual administrative actions and ensure all instances are updated to the latest secure version provided by the project.

## Impact

Successful exploitation of these vulnerabilities leads to unauthorized administrative access within the MISP platform. This facilitates the theft or modification of sensitive threat intelligence data, potential lateral movement through shared indicators, and the compromise of intelligence-sharing workflows. The breadth of data exposed depends on the specific MISP deployment and the sensitivity of the ingested threat feeds.

## Recommendation

Prioritized, concrete actions for detection engineering and security operations teams:

- Update all MISP instances to the latest available version provided by the MISP Project immediately to mitigate the underlying vulnerabilities.
- Audit administrative log files in MISP for suspicious role changes or unauthorized configuration modifications.
- Implement strict session management and access controls for all MISP accounts, especially those with high-level privileges.
- Monitor web application logs for unusual URL patterns or request parameters that deviate from standard usage by authorized analysts.
