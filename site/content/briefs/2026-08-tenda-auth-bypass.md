---
title: Authentication Bypass in Tenda AC1206 Web UI
slug: 2026-08-tenda-auth-bypass
description: Tenda AC1206 firmware version 15.03.06.23 contains an authentication bypass vulnerability in the /goform/telnet handler, allowing remote attackers to gain unauthorized access.
date: "2026-08-31T13:58:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:tenda:ac1206:15.03.06.23:*:*:*:*:*:*:*
tags:
  - vulnerability
  - network-security
  - web-application
vendors:
  - Tenda
products:
  - AC1206 (15.03.06.23)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-82693
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82693
rules:
  - title: Detect CVE-2026-82693 Exploitation - HTTP Request to /goform/telnet
    description: Detects exploitation attempts against Tenda AC1206 routers by monitoring for incoming HTTP requests to the vulnerable /goform/telnet endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate Tenda AC1206 devices from the public internet.
      owner: IT Operations
      due: 24h
      evidence: Critical severity vulnerability confirmed.
  mitigation_plan:
    - priority: immediate
      action: Check for and apply firmware updates from Tenda; restrict access to /goform/telnet.
      owner: IT Operations
      addresses: CVE-2026-82693
      evidence: NVD vulnerability notice.
---

A critical authentication bypass vulnerability has been identified in Tenda AC1206 firmware version 15.03.06.23. The flaw exists within the TendaTelnet function, located in the /goform/telnet file within the Web UI component. This vulnerability allows remote, unauthenticated attackers to interact with the device's administrative functions. The vulnerability has been publicly disclosed and is considered exploitable. Due to the nature of the device as a network-facing router, successful exploitation could lead to full system compromise, enabling attackers to modify device configurations, intercept traffic, or use the device as a pivot point within the local network. 

## Impact

The vulnerability carries a CVSS v3.1 base score of 10.0, indicating the highest level of severity. Unauthorized access to network infrastructure devices like the Tenda AC1206 exposes residential or small business environments to persistent threats, including traffic interception, DNS hijacking, and internal network reconnaissance.

## Recommendation

Prioritize the identification of Tenda AC1206 devices within the network inventory. Because this is a router-level vulnerability, detection engineering should prioritize network-based monitoring. Monitor for anomalous HTTP requests directed at the web management interface of identified Tenda devices. Implement network segmentation to isolate such devices from critical assets until firmware patches are applied by the vendor.
