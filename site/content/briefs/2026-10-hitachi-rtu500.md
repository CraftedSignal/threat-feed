---
title: Critical Vulnerabilities in End-of-Life Hitachi Energy RTU500 Firmware
slug: 2026-10-hitachi-rtu500
description: End-of-life Hitachi Energy RTU500 CMU firmware versions 11.x and prior are susceptible to multiple critical vulnerabilities, including authentication bypass and path traversal, which could allow remote attackers to compromise device integrity or disrupt industrial control operations.
date: "2026-10-06T17:12:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:rockwellautomation:1756-enbt\/a_firmware:3.2.6:*:*:*:*:*:*:*
  - cpe:2.3:o:rockwellautomation:1756-enbt\/a_firmware:3.6.1:*:*:*:*:*:*:*
  - cpe:2.3:o:windriver:vxworks:*:*:*:*:*:*:*:*
tags:
  - ics
  - energy
  - ot-security
  - vulnerability-management
vendors:
  - Hitachi Energy
  - Wind River
products:
  - RTU500 series CMU Firmware (<= 11.x)
  - VxWorks (6.x, 5.x and earlier)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authentication bypass vulnerability in the firmware update endpoint of Hitachi Energy RTU500 allows an unauthenticated attacker to upload arbitrary firmware through a crafted POST request.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A directory traversal vulnerability in the file upload functionality of Hitachi Energy RTU500 allows an unauthenticated attacker to write or overwrite arbitrary files on the device file system.
    confidence_band: high
cves:
  - id: CVE-2026-8066
    cvss: 9.1
    epss: 0.00736
  - id: CVE-2026-8067
    cvss: 6.5
    epss: 0.00324
  - id: CVE-2010-2965
    cvss: 9.8
    epss: 0.47371
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-06
  - https://www.cve.org/CVERecord?id=CVE-2026-8065
  - https://www.cve.org/CVERecord?id=CVE-2026-8066
  - https://www.cve.org/CVERecord?id=CVE-2026-8067
  - https://www.cve.org/CVERecord?id=CVE-2010-2965
  - https://www.cve.org/CVERecord?id=CVE-2014-9195
  - https://www.cve.org/CVERecord?id=CVE-2023-46143
action_plan:
  priority: immediate_escalation
  owners:
    - OT Security
    - Network Operations
  immediate_actions:
    - action: Upgrade RTU500 CMU Firmware to version 12.7.8 or 13.9.1
      owner: OT Security
      due: 72h
      evidence: Vendor recommendation in CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict access to web management and UDP port 17185 via network segmentation
      owner: Network Operations
      addresses: CVE-2026-8065, CVE-2026-8066, CVE-2010-2965
      evidence: General ICS hardening practice
---

Hitachi Energy has issued an advisory regarding multiple security vulnerabilities affecting legacy, end-of-life (EOL) RTU500 CMU firmware versions 11.x and earlier. These firmware versions, developed under historical industry standards, lack modern security controls such as robust authentication, encrypted communications, and integrity checks. Researchers reported that these legacy systems are susceptible to several high-severity flaws, including CVE-2026-8065, CVE-2026-8066, CVE-2026-8067, CVE-2010-2965, CVE-2014-9195, and CVE-2023-46143. 

These vulnerabilities permit unauthenticated remote attackers to upload arbitrary firmware, overwrite system files via directory traversal, or trigger device reboots, leading to potential operational disruption or unauthorized control of industrial hardware. Because these firmware versions are no longer maintained, Hitachi Energy explicitly advises upgrading to supported versions (12.7.8, 13.9.1, or later) to remediate these risks. Organizations relying on this equipment in critical energy sectors are at elevated risk if these devices remain exposed to network segments accessible by unauthorized entities.

## Impact

Successful exploitation of these vulnerabilities can lead to a complete loss of device availability, unauthorized modification of industrial control logic, and compromise of system integrity. Given the deployment of RTU500 devices within the global energy sector, these issues pose a significant risk to operational continuity. An attacker achieving exploitation could effectively disable remote terminal units, potentially impacting downstream industrial processes and resulting in service outages.

## Recommendation

- Upgrade all affected RTU500 CMU firmware instances to version 12.7.8, 13.9.1, or the latest available supported release immediately.
- Isolate EOL RTU500 hardware behind secure industrial firewalls to restrict inbound access to the web management interface and the WDB target agent debug service on UDP port 17185.
- Implement defense-in-depth strategies, including network segmentation and monitoring for anomalous traffic directed at OT control assets.
- Discontinue the use of firmware versions 11.x and earlier in production environments where security maintenance is required.
