---
title: Multiple Vulnerabilities in AMI AptioV Firmware
slug: 2026-10-ami-aptiov-vulnerabilities
description: Multiple vulnerabilities in AMI AptioV UEFI firmware allow local attackers to achieve arbitrary code execution, data manipulation, privilege escalation, and information disclosure.
date: "2026-10-14T16:24:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*
  - cpe:2.3:a:xwiki:xwiki:*:*:*:*:*:*:*:*
  - cpe:2.3:a:xwiki:xwiki:6.2:*:*:*:*:*:*:*
  - cpe:2.3:a:xwiki:xwiki:3.2:milestone3:*:*:*:*:*:*
  - cpe:2.3:a:xwiki:xwiki:14.7:rc1:*:*:*:*:*:*
vendors:
  - AMI
products:
  - AptioV
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1542
    technique_name: Pre-OS Boot
    evidence: Multiple vulnerabilities in AMI AptioV firmware allow local attackers to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Multiple vulnerabilities in AMI AptioV firmware allow local attackers to escalate privileges.
    confidence_band: high
cves:
  - id: CVE-2023-26464
    cvss: 7.5
    epss: 0.01905
  - id: CVE-2023-26472
    cvss: 9.9
    epss: 0.01107
  - id: CVE-2023-26474
    cvss: 9.9
    epss: 0.00787
  - id: CVE-2023-26476
    cvss: 7.5
    epss: 0.00894
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3925
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Architecture
  immediate_actions:
    - action: Inventory all physical hardware using AMI AptioV firmware.
      owner: IT Operations
      due: 72h
      evidence: General vulnerability impact necessitates identification of affected assets.
  mitigation_plan:
    - priority: medium_term
      action: Apply firmware updates provided by hardware manufacturers.
      owner: IT Operations
      addresses: CVE-2023-26463 through CVE-2023-26480
      evidence: Firmware vulnerabilities require vendor-specific patches for remediation.
---

The BSI has reported multiple security vulnerabilities affecting AMI AptioV, a widely used UEFI firmware implementation. These flaws impact the firmware's integrity and security posture, potentially allowing local attackers to execute arbitrary code, modify system data, escalate privileges, and gain unauthorized access to sensitive information. The vulnerabilities identified include CVE-2023-26463, CVE-2023-26464, CVE-2023-26465, CVE-2023-26466, CVE-2023-26467, CVE-2023-26468, CVE-2023-26469, CVE-2023-26470, CVE-2023-26471, CVE-2023-26472, CVE-2023-26473, CVE-2023-26474, CVE-2023-26475, CVE-2023-26476, CVE-2023-26477, CVE-2023-26478, CVE-2023-26479, and CVE-2023-26480. Because these issues exist at the firmware level, exploitation could lead to persistent compromise that survives operating system reinstallation, making detection and remediation significantly more complex for enterprise environments. Organizations should prioritize checking vendor-specific firmware update channels for patches addressing these identifiers.

## Impact

Successful exploitation of these vulnerabilities allows local attackers to compromise the foundation of the system boot process. This can result in full control over the hardware, bypassing OS-level security controls, persistent unauthorized access, and the exfiltration of sensitive data that would otherwise be protected by Secure Boot or other platform security features. These flaws affect a broad range of hardware platforms that utilize AMI AptioV firmware.

## Recommendation

- Identify systems utilizing AMI AptioV firmware across the fleet via hardware inventory and BIOS/UEFI version reporting.
- Coordinate with hardware OEMs (Original Equipment Manufacturers) to identify and deploy applicable firmware updates addressing the listed CVEs.
- Implement secure boot and firmware integrity monitoring where supported to detect unauthorized modifications to the UEFI environment.
- Prioritize patch management for high-value assets and systems where the impact of persistent firmware compromise is most severe.
