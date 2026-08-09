---
title: Remote Command Injection in Shenzhen Aitemi M300 Wi-Fi Repeater
slug: 2026-08-m300-repeater-rce
description: The Shenzhen Aitemi M300 Wi-Fi Repeater is vulnerable to unauthenticated remote command injection via the /protocol.csp endpoint, allowing arbitrary system execution through parameter manipulation.
date: "2026-08-09T11:45:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Shenzhen Aitemi
products:
  - M300 Wi-Fi Repeater (r0-ea7890a)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Performing a manipulation of the argument enable/name/mac results in command injection.
    confidence_band: high
cves:
  - id: CVE-2026-19348
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19348
rules:
  - title: Detects CVE-2026-19348 Exploitation - Remote Command Injection in M300 Repeater
    description: Detects exploitation of CVE-2026-19348 by identifying command injection attempts via the /protocol.csp endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict network access to the management interface of Shenzhen Aitemi M300 devices.
      owner: IT Operations
      due: 24h
      evidence: Device is vulnerable to unauthenticated remote command injection.
  mitigation_plan:
    - priority: immediate
      action: Deploy detection rules for /protocol.csp traffic.
      owner: SOC
      addresses: CVE-2026-19348
      evidence: Public exploit code is available.
---

A critical command injection vulnerability (CVE-2026-19348) has been identified in the Shenzhen Aitemi M300 Wi-Fi Repeater, specifically affecting firmware version r0-ea7890a. The vulnerability originates from the unsafe use of the 'sprintf' function within the '/protocol.csp' handler. An unauthenticated, remote attacker can manipulate the 'enable', 'name', or 'mac' parameters to inject and execute arbitrary commands on the underlying operating system. Because public exploit code is available, this vulnerability poses a significant risk to organizations using these devices in their network infrastructure. Defenders should restrict access to the management interface of affected devices and monitor for suspicious HTTP traffic directed at the '/protocol.csp' URI.

## Impact

Successful exploitation allows unauthenticated remote code execution with the privileges of the web service. This could result in full device compromise, persistence, or use of the device as a pivot point for further lateral movement within the local network. Given that this is a Wi-Fi repeater, compromise provides an attacker with a strategic vantage point to intercept or manipulate local wireless traffic.

## Recommendation

- Identify and inventory all Shenzhen Aitemi M300 Wi-Fi Repeaters on the network.
- Implement network-level access controls (ACLs) to restrict access to the management interface of the M300 devices to trusted administrative IP addresses only.
- Monitor network traffic for HTTP POST or GET requests to '/protocol.csp' containing shell metacharacters (e.g., ;, |, &, $, `) in the 'enable', 'name', or 'mac' parameters.
- Contact the vendor, Shenzhen Aitemi, for firmware updates that address the unsafe usage of 'sprintf' in the protocol handler.
