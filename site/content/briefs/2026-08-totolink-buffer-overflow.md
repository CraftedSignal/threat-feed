---
title: Remote Stack-based Buffer Overflow in TOTOLINK A800R
slug: 2026-08-totolink-buffer-overflow
description: An authenticated remote attacker can trigger a stack-based buffer overflow in the TOTOLINK A800R router via the setIpQosRules function, potentially leading to arbitrary code execution.
date: "2026-08-14T08:06:33Z"
lastmod: "2026-08-14T10:07:48Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - remote-code-execution
  - cve-2026-19811
  - router-vulnerability
  - cve-2026-19812
  - buffer-overflow
  - router
  - rce
  - vulnerability
  - totolink
vendors:
  - TOTOLINK
products:
  - A800R (4.1.2cu.5137_B20200730)
  - A800R
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19811
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19811
  - https://github.com/panda666-888/vuls/blob/main/totolink/a800r/setIpQosRules.md
  - https://vuldb.com/cve/CVE-2026-19811
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19812
  - https://vuldb.com/cve/CVE-2026-19812
  - https://github.com/panda666-888/vuls/blob/main/totolink/a800r/UploadCustomModule.md
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19814
  - https://vuldb.com/vuln/389950
rules:
  - title: Detects CVE-2026-19811 Exploitation - Buffer Overflow Attempt in setIpQosRules
    description: Detects potentially malicious HTTP POST requests to the setIpQosRules function where the Comment argument contains an unusually long string, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-19814 Exploitation Attempt - HTTP Request to setMacQos
    description: Detects potential exploitation attempts of the setMacQos function in TOTOLINK A800R by monitoring for HTTP requests to the target script containing suspiciously long macAddress parameters
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy the suggested Sigma rule to identify exploitation attempts against network edge devices.
      owner: Detection Engineering
      due: 24h
      evidence: Public exploit code availability for CVE-2026-19811.
  enrichment_needed:
    - item: Verify vendor patch status for TOTOLINK A800R
      owner: CTI
      reason: Ensure remediation path is available beyond current workarounds.
      evidence: Source does not list a specific patch identifier.
  mitigation_plan:
    - priority: immediate
      action: Disable remote management web interface on all exposed TOTOLINK routers.
      owner: IT Operations
      addresses: CVE-2026-19811
      evidence: Vulnerability is remotely exploitable via the web management interface.
updates:
  - at: "2026-08-14T10:07:35Z"
    level: L2
    summary: added coverage for A800R
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19812
  - at: "2026-08-14T10:07:48Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-19814 Exploitation Attempt - HTTP Request to setMacQos'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19814
---

A critical security vulnerability has been identified in the TOTOLINK A800R router, specifically affecting firmware version 4.1.2cu.5137_B20200730. The flaw resides within the firewall.so component, specifically in the setIpQosRules function invoked by the /cgi-bin/cstecgi.cgi script. An attacker can exploit this via a stack-based buffer overflow by manipulating the 'Comment' argument. The vulnerability is remotely exploitable by an authenticated user and has been assigned CVE-2026-19811. Public exploit code is currently available, increasing the risk of active exploitation against vulnerable network devices. Given the nature of the device as an edge gateway, successful exploitation could provide an attacker with persistent access to the network.

## Attack Chain

1. Attacker performs reconnaissance to identify the target web management interface on a publicly accessible TOTOLINK A800R router.
2. Attacker gains valid credentials for the administrative or user portal through credential stuffing or brute-forcing.
3. Attacker accesses the Quality of Service (QoS) settings page which invokes the /cgi-bin/cstecgi.cgi CGI script.
4. Attacker crafts a malicious HTTP POST request targeting the setIpQosRules function.
5. Attacker injects a specially crafted, oversized string into the 'Comment' parameter of the HTTP request.
6. The firewall.so component fails to properly validate the input size, resulting in a stack-based buffer overflow.
7. The overflow overwrites the return address on the stack, diverting program execution to attacker-controlled shellcode.
8. Attacker gains execution context, potentially leading to full system compromise or persistence on the device.

## Impact

Successful exploitation allows an authenticated remote attacker to achieve arbitrary code execution on the TOTOLINK A800R device. This compromises the integrity and confidentiality of traffic passing through the router, facilitates lateral movement into the local network, and provides a platform for further exploitation of connected internal systems.

## Recommendation

* Monitor web server logs for anomalies targeting /cgi-bin/cstecgi.cgi and specifically unusual values or excessive lengths in the 'Comment' parameter.
* Disable remote management access for the router's web interface, restricting access to trusted local IP addresses only.
* Evaluate the need for the device's current firmware version and apply vendor security updates if a patch addressing CVE-2026-19811 is available from TOTOLINK.
* Audit access logs for any unauthorized authentication attempts or patterns consistent with credential exploitation.
