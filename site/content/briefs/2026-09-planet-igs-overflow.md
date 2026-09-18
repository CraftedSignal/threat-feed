---
title: Stack-based Buffer Overflow in PLANET IGS-5225-8P2T4S Managed Switches
slug: 2026-09-planet-igs-overflow
description: A stack-based buffer overflow vulnerability in the web server of PLANET IGS-5225-8P2T4S industrial managed switches allows authenticated remote attackers to achieve denial of service or remote code execution via CVE-2026-81944.
date: "2026-09-18T18:08:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:planet:igs-5225-8p2t4s_firmware:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - industrial-control-systems
  - network-security
  - cve-2026-81944
vendors:
  - PLANET
products:
  - IGS-5225-8P2T4S (< 1.2412b260707 and < 2.2412b260519)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Insufficient bounds checking on data copied into a stack buffer allows a remote authenticated attacker to cause a denial of service or potentially execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-81944
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81944
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware to version 1.2412b260707 (V1) or 2.2412b260519 (V2)
      owner: IT Operations
      addresses: CVE-2026-81944
      evidence: NVD vulnerability disclosure
---

PLANET IGS-5225-8P2T4S industrial managed switches (V1 and V2 firmware) contain a critical stack-based buffer overflow vulnerability identified as CVE-2026-81944. The flaw exists within the device's integrated web server, which fails to perform adequate bounds checking when copying user-supplied input into stack-based buffers. This vulnerability can be exploited by an authenticated remote attacker to overwrite memory, resulting in a denial-of-service condition or the potential for arbitrary code execution on the underlying operating system. The vulnerability affects firmware versions prior to 1.2412b260707 for V1 units and versions prior to 2.2412b260519 for V2 units. Given the deployment of these devices in industrial environments, successful exploitation could lead to significant operational disruption or unauthorized control over network infrastructure.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to compromise the integrity and availability of industrial network switches. Impact includes device crashes (denial of service) or full remote code execution, which may permit persistent access to the network or the ability to manipulate traffic flowing through the industrial switch. Organizations in manufacturing, energy, and utility sectors utilizing these switches are at the highest risk.

## Recommendation

- Upgrade PLANET IGS-5225-8P2T4S (V1) firmware to version 1.2412b260707 or later.
- Upgrade PLANET IGS-5225-8P2T4S (V2) firmware to version 2.2412b260519 or later.
- Restrict access to the web management interface of industrial switches to trusted, hardened management workstations via VLAN segmentation and firewall rules.
- Monitor for anomalous HTTP traffic directed at the web management interfaces of industrial networking equipment.
