---
title: Critical Vulnerabilities in Digital Watchdog VMAX DVR and NVR Products
slug: 2026-09-digital-watchdog-vmax-vulnerabilities
description: Multiple high-severity vulnerabilities in Digital Watchdog VMAX series devices allow unauthenticated remote attackers to bypass authentication, gain root access via hard-coded credentials, and execute arbitrary system commands.
date: "2026-09-15T16:31:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - critical-infrastructure
  - ics
  - authentication-bypass
  - remote-code-execution
vendors:
  - Digital Watchdog
products:
  - VMAX A1 G4 DVRs (all)
  - VMAX IP G4 NVRs (all)
  - VMAX A1 PLUS (all)
  - VA1G4 Recorder (all)
  - VG4 Recorder (all)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The affected products are vulnerable to an authentication bypass that allows unauthenticated remote attackers to disclose sensitive device information, including administrator credentials in plaintext, by sending crafted HTTP(S) requests.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The affected products use hard-coded credentials, which could allow remote access to files with root privileges where FTP is reachable.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-01
  - https://www.cve.org/CVERecord?id=CVE-2026-68953
  - https://www.cve.org/CVERecord?id=CVE-2026-66890
  - https://www.cve.org/CVERecord?id=CVE-2026-68070
  - https://www.cve.org/CVERecord?id=CVE-2026-68950
  - https://www.cve.org/CVERecord?id=CVE-2026-66887
  - https://www.cve.org/CVERecord?id=CVE-2026-66372
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all Digital Watchdog VMAX firmware to the latest versions released after 2026-09-15
      owner: IT Operations
      due: 24h
      evidence: Remediation note in CISA advisory ICSA-26-258-01
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to device management ports and place devices in an isolated management VLAN
      owner: IT Operations
      addresses: All listed CVEs
      evidence: Vendor recommendation and ICS best practices
---

Multiple critical vulnerabilities (CVE-2026-68953, CVE-2026-66890, CVE-2026-68070, CVE-2026-68950, CVE-2026-66887, CVE-2026-66372) have been identified in the Digital Watchdog VMAX DVR and NVR product lines. These vulnerabilities, primarily involving missing authentication (CWE-306) and the use of hard-coded credentials (CWE-798), allow unauthenticated remote attackers to gain full administrative or root-level control of affected devices. The vulnerabilities stem from predictable PRNG seeds, hard-coded FTP credentials that provide root-level file access, and missing authentication on critical functions that allow command execution. These products are widely deployed in commercial, government, healthcare, and transportation sectors. Exploitation allows an attacker to access surveillance footage, modify device configurations, or pivot into the internal network.

## Impact

Successful exploitation grants an attacker full administrative control over the DVR or NVR device. The impact includes unauthorized access to live and recorded surveillance video, manipulation of security configurations, and the ability to use the compromised hardware as a jump box or pivot point to conduct further lateral movement within the target's internal network. Given the typical deployment of these devices in critical infrastructure, this presents a significant risk to organizational confidentiality and network integrity.

## Recommendation

* Prioritize the immediate application of updated firmware provided by Digital Watchdog for all VMAX A1 G4, VMAX IP G4, VMAX A1 PLUS, VA1G4, and VG4 recorder models available at https://digital-watchdog.com/downloads/.
* Restrict access to management interfaces (Web UI and FTP services) to authorized, trusted IP addresses using internal network firewalls or ACLs.
* Monitor internal network traffic for unauthorized FTP and HTTP administrative access originating from DVR/NVR devices.
* Isolate these video surveillance devices on a dedicated, non-routable management VLAN to minimize the potential for lateral movement.
