---
title: Command Injection Vulnerability in VIVOTEK Camera Firmware
slug: 2026-09-vivotek-firmware-rce
description: A critical command injection vulnerability (CVE-2026-22755) in various VIVOTEK network camera firmware allows unauthenticated remote attackers to execute arbitrary commands with root privileges.
date: "2026-09-29T16:25:01Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:vivotek:camera_firmware:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ics
  - cve-2026-22755
  - remote-access
vendors:
  - VIVOTEK
products:
  - VIVOTEK Camera Firmware (FD9187, FD9189, FD9365, FD9387, FD9389, FD9391, FE9180, FE9191, FE9382, FE9391, IB9365, IB9387, IB9389, IB939, IP9165, IP9171, IP9172, IP9181, IP9191, IT9389, MA9321, MA9322, MS9321, MS9390, TB9330, FD8365, FD8365v2, FD9165, FD9171, FD9371, FD9381, FE9181, FE9381, FE9582, IB93587LPR, IB9371, IB9381)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of this vulnerability may allow attackers to achieve remote command execution on affected devices.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A command injection vulnerability has been identified in firmware modules used by multiple network camera models.
    confidence_band: high
cves:
  - id: CVE-2026-22755
    epss: 0.20439
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-272-03
  - https://www.vivotek.com/en-US/resource/download-center/software-app-vadp-package
  - https://www.cve.org/CVERecord?id=CVE-2026-22755
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all VIVOTEK devices and ensure firmware is upgraded to the latest version.
      owner: IT Operations
      due: 24h
      evidence: Mitigation section of ICSA-26-272-03
    - action: Remove internet-facing access for all VIVOTEK camera management interfaces.
      owner: Security Operations
      due: 24h
      evidence: Recommended practices section of ICSA-26-272-03
  mitigation_plan:
    - priority: immediate
      action: Isolate cameras behind firewalls and VPNs.
      owner: IT Operations
      addresses: CVE-2026-22755
      evidence: Recommended practices section of ICSA-26-272-03
---

VIVOTEK has disclosed a critical command injection vulnerability (CVE-2026-22755) affecting a wide range of its network camera models. This vulnerability allows an unauthenticated, remote attacker to execute arbitrary commands on the affected devices. Due to the nature of the vulnerability, execution occurs with root-level privileges, resulting in the potential for a full compromise of the camera system.

The vulnerability is classified as CWE-77 (Improper Neutralization of Special Elements used in a Command) and has been assigned a CVSS v3.1 score of 10.0 (Critical). The flaw exists in the firmware modules of the impacted hardware. While there are no confirmed reports of in-the-wild exploitation at the time of disclosure, a proof-of-concept exploit exists in the public domain. Security teams should prioritize patching or isolating these devices, as compromised cameras can be leveraged for network reconnaissance, unauthorized surveillance, or as entry points into wider organizational networks.

## Impact

Successful exploitation leads to a complete loss of confidentiality, integrity, and availability of the affected VIVOTEK camera devices. As these systems are frequently deployed across critical infrastructure sectors including government, transportation, energy, and financial services, the impact includes unauthorized access to video streams, potential pivot points into internal industrial control system (ICS) networks, and the ability to brick or disrupt critical monitoring infrastructure. Affected devices are deployed worldwide.

## Recommendation

Prioritize the following actions to secure VIVOTEK assets:
- Immediately identify all deployed VIVOTEK camera models listed in the affected products section.
- Download and install the latest firmware updates provided by VIVOTEK through their official download center.
- Implement network segmentation to isolate all VIVOTEK cameras from internet-facing environments.
- Ensure all control system devices are protected by firewalls, preventing direct access from the public internet or untrusted business network segments.
- If remote access is required, enforce the use of secure, authenticated VPN tunnels rather than direct port forwarding or web-accessible management interfaces.
