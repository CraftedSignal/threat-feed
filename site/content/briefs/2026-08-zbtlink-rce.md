---
title: Unauthenticated RCE in Zbtlink Router Firmware
slug: 2026-08-zbtlink-rce
description: Multiple Zbtlink router models contain an unauthenticated command injection vulnerability in the infosrvd service, enabling root-level remote code execution via crafted UDP packets.
date: "2026-08-27T13:40:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Zbtlink
products:
  - WE1326
  - WE357
  - WE5926
  - WE5926-WD
  - WE826-Q
  - WE826-T2
  - WE826-WD
  - WG108
  - WG3526
  - WE2426-C
  - WE5926-EC_QP
  - WF3526-P
  - CTN720-W1
  - LF-1541
  - MT7620N
  - WRC1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote unauthenticated attacker can send a crafted UDP packet to execute arbitrary commands as root.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: A remote unauthenticated attacker can send a crafted UDP packet to execute arbitrary commands as root.
    confidence_band: high
cves:
  - id: CVE-2026-74233
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74233
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block UDP port 9992 on perimeter firewalls for all Zbtlink router devices.
      owner: IT Operations
      due: 24h
      evidence: Service infosrvd listens on UDP/9992 and allows root RCE.
---

Zbtlink router firmware for numerous models, including the WE, WG, and WRC series, contains a critical command injection vulnerability (CVE-2026-74233) within the infosrvd service. This service, which typically listens on UDP port 9992, fails to enforce authentication correctly due to the use of hardcoded salts and a vulnerable wildcard MAC address bypass mechanism. A remote, unauthenticated attacker can exploit this flaw by sending a specifically crafted UDP packet to the target device. Successful exploitation results in the execution of arbitrary commands with root privileges. Given the nature of these devices as network edge equipment, successful exploitation allows attackers to gain full control of the router, potentially facilitating further network lateral movement or traffic interception. Defenders should identify affected Zbtlink hardware within their network perimeter and apply vendor firmware updates or restrict access to the infosrvd service.

## Impact

Successful exploitation allows for full administrative control over the affected Zbtlink routers, effectively compromising the integrity and security of the network traffic passing through these devices. This vulnerability affects a wide array of SOHO and industrial router models widely distributed across various sectors. If exploited, an attacker could maintain persistent access, exfiltrate sensitive data, or use the device as a pivot point to conduct further attacks against internal network resources.

## Recommendation

* Immediately audit network perimeters to identify Zbtlink devices listed in the affected products section and ensure they are isolated from public-facing internet segments.
* Disable the infosrvd service on affected devices if a firmware update is not yet available, or block UDP port 9992 at the firewall for any traffic originating from untrusted sources.
* Prioritize the application of vendor patches for CVE-2026-74233 across all identified Zbtlink router deployments.
