---
title: Command Injection in PLANET IGS-5225 Industrial Switches
slug: 2026-09-planet-switch-rce
description: An OS command injection vulnerability in the web interface of PLANET IGS-5225-8P2T4S switches allows authenticated remote attackers to execute arbitrary commands with root privileges.
date: "2026-09-18T18:08:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:planet_technology:igs_5225_8p2t4s:*:*:*:*:*:*:*:*
vendors:
  - PLANET Technology
products:
  - IGS-5225-8P2T4S (V1 < 1.2412b260707, V2 < 2.2412b260519)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: User-supplied input is passed to system() without sufficient filtering, allowing a remote authenticated attacker to execute arbitrary commands
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allowing a remote authenticated attacker to execute arbitrary commands on the underlying operating system and escalate privileges to root.
    confidence_band: high
cves:
  - id: CVE-2026-81942
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81942
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade IGS-5225-8P2T4S to 1.2412b260707 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-81942 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface network access to authorized segments
      owner: OT Security
      addresses: CVE-2026-81942
      evidence: Vulnerability allows remote execution; access control limits vector
---

PLANET Technology IGS-5225-8P2T4S industrial managed switches (V1 and V2) are affected by an OS command injection vulnerability within the embedded web server. The flaw arises from improper sanitization of user-supplied input before passing it to the system() function. An authenticated remote attacker can exploit this weakness to execute arbitrary commands on the device's underlying Linux-based operating system. Successful exploitation results in full control over the switch, allowing the attacker to escalate privileges to the root level. This vulnerability impacts V1 firmware versions prior to 1.2412b260707 and V2 firmware versions prior to 2.2412b260519. Given the nature of industrial control systems (ICS) and networking infrastructure, compromise of these devices can lead to persistent network interception, lateral movement into OT environments, or denial-of-service conditions.

## Impact

Successful exploitation allows a remote authenticated attacker to gain root-level access to industrial networking infrastructure. This can facilitate unauthorized configuration changes, exfiltration of sensitive network traffic, and potential disruption of critical operational technology (OT) processes. As these switches are commonly used in industrial deployments, the risk of pivot into segmented network zones is high.

## Recommendation

Update all affected PLANET IGS-5225-8P2T4S devices to the latest available firmware versions immediately (V1: >= 1.2412b260707; V2: >= 2.2412b260519). Until patching is complete, restrict access to the web-based management interface to trusted management subnets only and disable HTTP/HTTPS access where not strictly required for operations.
