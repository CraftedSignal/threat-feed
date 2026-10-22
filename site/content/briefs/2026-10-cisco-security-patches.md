---
brief_id: brief-2026-10-22-cisco-security-patches
event_id: brief-2026-10-22-cisco-security-patches
revision: 1
activity_at: "2026-10-22T10:47:10Z"
title: Cisco Security Updates for Expressway, Unified Communications, and Snort 3
slug: 2026-10-cisco-security-patches
description: Cisco has patched 34 vulnerabilities, including critical-severity remote code execution and authentication bypass flaws, affecting Expressway Series, Unified Communications products, and Snort 3.
date: "2026-10-22T10:47:10Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; specific CVEs identified.
tags:
  - vulnerability
  - cisco
  - patch-management
vendors:
  - Cisco
products:
  - Expressway Series (< X15.5.20)
  - Unified Communications Manager
  - Unified Communications Manager IM & Presence Service
  - Unified Communications Manager Session Management Edition
  - Unity Connection
  - Emergency Responder
  - Prime Collaboration Deployment
  - Snort 3 (< 3.12.4.0)
  - Cyber Vision (< 3.12.4.0)
  - CDFW (< 3.12.4.0)
  - Meraki MX (< 3.12.4.0)
  - CSA
  - Secure Firewall ASA (< 3.12.4.0)
  - Secure FMC (< 3.12.4.0)
  - Secure FTD
  - UTD for IOS XE
  - IOS XR
  - Secure Client
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A successful exploit could allow the attacker to execute arbitrary commands as root on the underlying operating system of an affected device.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The use of persistent cookies and insufficient validation of client certificates in certain configurations could allow attackers to connect to the database service.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A high-severity privilege escalation bug in Secure Client’s Secure Firewall Posture module (CVE-2026-76462).
    confidence_band: high
cves:
  - id: CVE-2026-76462
    cvss: 5.5
    kev_status: "false"
  - id: CVE-2026-76466
    cvss: 9.8
    kev_status: "false"
references:
  - https://www.securityweek.com/cisco-patches-34-vulnerabilities-across-multiple-products/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch affected Cisco infrastructure to the versions specified in the advisory.
      owner: IT Operations
      due: 72h
      evidence: Cisco security advisory patch guidance.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Expressway Series to X15.5.20 and Snort 3 to 3.12.4.0.
      owner: IT Operations
      addresses: CVE-2026-76466 and general Snort 3 vulnerabilities.
      evidence: Source advisory reporting on patch availability.
---

Cisco released security updates addressing 34 vulnerabilities across multiple product lines, including Expressway Series, Unified Communications products, Snort 3, IOS XR, and Secure Client. The vulnerabilities include critical-severity flaws capable of remote code execution (RCE), authentication bypass, and denial-of-service (DoS). Cisco reports no evidence of active exploitation in the wild as of the release date.

## Impact
Successful exploitation of critical vulnerabilities, such as CVE-2026-76466 in the Expressway Series, could allow an unauthenticated attacker to execute arbitrary commands with root privileges on the underlying operating system. Other vulnerabilities in Unified Communications and Snort 3 permit unauthorized resource access, authentication bypass, or arbitrary command execution.

## Recommendation
- Inventory systems running Cisco Expressway Series, Unified Communications Manager (and related products), and Snort 3 deployments.
- Upgrade Cisco Expressway Series to version X15.5.20 or later.
- Upgrade Snort 3 to version 3.12.4.0 or later.
- Apply the corresponding security updates for peripheral products including Cyber Vision, CDFW, Meraki MX, Secure Firewall ASA, Secure FMC, Secure FTD, and UTD for IOS XE.
- Monitor Cisco’s official security advisories page for specific upgrade paths for impacted Unified Communications products.
