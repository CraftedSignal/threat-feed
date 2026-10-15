---
title: Unauthenticated Remote Code Execution in Jooan JA-A12 IP Cameras
slug: 2026-10-jooan-rce
description: Jooan JA-A12 IP cameras running specific firmware versions are vulnerable to unauthenticated remote code execution via a hard-coded credential flaw that allows command injection into the jooandiag daemon.
date: "2026-10-15T22:40:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:jooan:ja-a12:-:*:*:*:*:*:*:*
tags:
  - iot
  - rce
  - vulnerability
  - cve-2026-111281
vendors:
  - Jooan
products:
  - JA-A12 IP camera (009_20171107, 05.02.31.105)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit this flaw by sending a crafted HTTP request to the device.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: jooandiag daemon execute their commands through /bin/sh
    confidence_band: high
cves:
  - id: CVE-2026-111281
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111281
rules:
  - title: Detect CVE-2026-111281 Exploitation Attempt
    description: Detects exploitation attempts against CVE-2026-111281 where an attacker sends a malicious command request to the IP camera diagnostic endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy web server rule to detect exploitation attempts against IP cameras
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-111281
  mitigation_plan:
    - priority: immediate
      action: Isolate affected Jooan JA-A12 cameras from public network exposure
      owner: IT Operations
      addresses: CVE-2026-111281
      evidence: NVD vulnerability disclosure
---

Researchers have identified a critical remote code execution (RCE) vulnerability, tracked as CVE-2026-111281, affecting Jooan JA-A12 IP cameras. The vulnerability stems from the use of hard-coded credentials within the device firmware, specifically versions 009_20171107 and 05.02.31.105. An unauthenticated attacker can exploit this flaw by sending a crafted HTTP request to the device. By targeting the '/goform/SingleHandlebyCommand' endpoint with the 'singleCMD=SetDiagMode' parameter, an attacker can manipulate the jooandiag daemon to execute arbitrary commands. These commands are executed with root privileges via /bin/sh, granting the attacker full control over the affected IP camera. This flaw is particularly concerning given the device's role in network surveillance, as successful exploitation enables persistent access to internal network environments and the ability to intercept or manipulate video feeds.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.8, indicating a high potential for widespread compromise. Successful exploitation grants attackers root-level access, allowing them to install persistent backdoors, pivot into the local network, or exfiltrate sensitive surveillance data. Organizations relying on Jooan JA-A12 cameras for physical security are at risk of complete surveillance system subversion.

## Recommendation

- Identify and isolate all Jooan JA-A12 cameras from the internet to prevent unauthenticated access.
- Inspect network traffic logs for HTTP POST requests to the /goform/SingleHandlebyCommand endpoint containing the singleCMD=SetDiagMode parameter.
- Monitor for anomalous process execution on internal camera devices if such telemetry is available via embedded diagnostics.
- Upgrade affected firmware to the latest secure version provided by the manufacturer or, if unavailable, replace the vulnerable hardware units.
