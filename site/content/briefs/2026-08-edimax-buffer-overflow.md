---
title: Stack-based Buffer Overflow in Edimax EW-7478APC
slug: 2026-08-edimax-buffer-overflow
description: Edimax EW-7478APC version 1.04 is vulnerable to a stack-based buffer overflow in the formWanTcpipSetup function, allowing for remote code execution via the pppUserName parameter.
date: "2026-08-17T00:42:27Z"
lastmod: "2026-08-17T00:42:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - buffer-overflow
  - router
  - cve-2026-19961
  - vulnerability
  - network-device
vendors:
  - Edimax
products:
  - EW-7478APC (1.04)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-19959
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19959
  - https://vuldb.com/vuln/391136
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19961
  - https://vuldb.com/vuln/391138
rules:
  - title: Detect Exploitation of CVE-2026-19959 - Web Request to formWanTcpipSetup
    description: Detects HTTP requests to the vulnerable formWanTcpipSetup endpoint on Edimax devices.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-19961 Exploitation Attempt - Remote Buffer Overflow
    description: Detects exploitation attempts against CVE-2026-19961 by monitoring HTTP requests to the /goform/formWlSiteSurvey endpoint with excessively long selSSID parameters.
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
    - action: Restrict management interface access via network segmentation or firewall rules
      owner: IT Operations
      due: 24h
      evidence: Critical vulnerability with public exploit availability
  hunt_leads:
    - lead: Look for POST requests to /goform/formWanTcpipSetup followed by unusual outbound traffic from the device
      technique_id: T1190
      data_needed:
        - Web logs
        - Network flows
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary code execution
  mitigation_plan:
    - priority: immediate
      action: Disable remote management features on all Edimax EW-7478APC devices
      owner: IT Operations
      addresses: CVE-2026-19959
      evidence: No vendor patch available
updates:
  - at: "2026-08-17T00:42:39Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-19961 Exploitation Attempt - Remote Buffer Overflow'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19961
---

A stack-based buffer overflow vulnerability has been identified in the Edimax EW-7478APC router, specifically within firmware version 1.04. The vulnerability resides in the formWanTcpipSetup function, accessible via the /goform/formWanTcpipSetup endpoint. An authenticated remote attacker can trigger this overflow by sending a specially crafted input to the pppUserName parameter. This flaw allows for the execution of arbitrary code on the affected device or can result in a denial-of-service condition. Publicly available exploit code exists, increasing the risk of exploitation. The vendor has not provided a patch or response to the disclosure. Defenders should note that this vulnerability requires authenticated access, but its remote nature and the availability of exploit material pose a significant risk to internal network segments where these devices are deployed.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable Edimax EW-7478APC management interfaces.
2. Attacker obtains valid administrative or user credentials via secondary means (e.g., credential stuffing or default password exploitation).
3. Attacker authenticates to the web-based management interface.
4. Attacker crafts a malicious HTTP POST request targeting the /goform/formWanTcpipSetup endpoint.
5. Attacker injects a long string payload into the pppUserName parameter of the POST body.
6. The web server process fails to perform sufficient boundary checks on the pppUserName input before copying it into a stack-based buffer.
7. The overflow overwrites the return address, enabling redirection of execution flow to arbitrary attacker-supplied shellcode.
8. Final objective is achieved: arbitrary command execution or system crash.

## Impact

Successful exploitation allows for complete compromise of the router, potentially providing an attacker with a pivot point into the local network. With a CVSS v3.1 score of 9.9, this vulnerability represents a critical risk to small office and home office (SOHO) deployments. If exploited, attackers could intercept traffic, perform man-in-the-middle attacks, or deploy further malicious payloads. Given the lack of a vendor patch, the only effective mitigation is to restrict management interface access to trusted networks or replace affected hardware.

## Recommendation

* Restrict access to the management web interface of all Edimax EW-7478APC devices to a dedicated management VLAN or trusted IP addresses via firewall rules.
* Monitor internal network traffic for unauthorized HTTP POST requests directed at /goform/formWanTcpipSetup.
* Audit logs for failed authentication attempts preceding any interaction with management endpoints.
* Isolate affected devices from the internet until a firmware update is provided by the vendor.
