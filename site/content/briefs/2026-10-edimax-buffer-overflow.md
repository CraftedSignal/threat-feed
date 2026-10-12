---
title: Remote Code Execution in Edimax BR-6208AC via Buffer Overflow
slug: 2026-10-edimax-buffer-overflow
description: A critical buffer overflow vulnerability in the Edimax BR-6208AC router allows unauthenticated remote code execution via manipulation of the ifname argument in the /goform/formWlSiteSurvey handler.
date: "2026-10-12T18:31:25Z"
lastmod: "2026-10-12T18:31:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:edimax:br-6208ac_firmware:1.32:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-security
  - edimax
  - eol
  - iot
  - remote-code-execution
vendors:
  - Edimax
products:
  - BR-6208AC (1.32)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This manipulation of the argument ifname causes buffer overflow. Remote exploitation of the attack is possible.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely via manipulation of the argument ateBW.
    confidence_band: high
cves:
  - id: CVE-2026-108914
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108914
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108915
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108917
rules:
  - title: Detect CVE-2026-108915 - Attempted Exploitation via formWlanMP
    description: Detects exploitation attempts against CVE-2026-108915 by monitoring for HTTP requests to the vulnerable formWlanMP endpoint with long ateBW parameters.
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
    - action: Isolate affected Edimax BR-6208AC routers from external-facing networks.
      owner: IT Operations
      due: 24h
      evidence: Device is EOL and vulnerable to remote exploitation.
  mitigation_plan:
    - priority: immediate
      action: Replace legacy Edimax BR-6208AC hardware.
      owner: IT Operations
      addresses: CVE-2026-108914
      evidence: Device is end-of-life and no patch will be provided.
updates:
  - at: "2026-10-12T18:31:41Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-108915 - Attempted Exploitation via formWlanMP'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108915
  - at: "2026-10-12T18:31:48Z"
    level: L2
    summary: added coverage for BR-6208AC (1.32)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108917
---

A critical buffer overflow vulnerability has been identified in the Edimax BR-6208AC router running firmware version 1.32. The vulnerability resides within the /goform/formWlSiteSurvey handler, where improper sanitization of the ifname argument allows an unauthenticated, remote attacker to trigger a buffer overflow. This flaw can be leveraged to achieve remote code execution on the affected network device. The vulnerability is publicly documented with available exploit code. Because the Edimax BR-6208AC is an end-of-life product, the vendor has not provided a security patch, leaving devices permanently exposed to this vector. Defenders should prioritize isolating these legacy devices from the internet or replacing them, as they cannot be secured against this specific exploit.

## Impact

The vulnerability poses a severe risk of unauthorized remote control over network infrastructure. As the device serves as a perimeter gateway, successful exploitation could lead to full system compromise, traffic interception, or the device being utilized as an entry point for lateral movement into the internal network. Since the product is end-of-life and unsupported, there is no path to remediation through official firmware updates.

## Recommendation

1. Inventory and identify all Edimax BR-6208AC devices within the network environment.
2. Implement strict access control lists on edge firewalls to block external traffic directed at the web management interfaces of identified routers.
3. Decommission and replace end-of-life hardware that is confirmed to be affected by CVE-2026-108914.
4. Monitor network traffic for HTTP POST or GET requests targeting the /goform/formWlSiteSurvey URI, which may indicate exploitation attempts.
