---
title: Remote Command Injection in Tenda CH22 Firmware
slug: 2026-08-tenda-ch22-command-injection
description: Tenda CH22 router firmware version 1.0.0.1 is vulnerable to unauthenticated remote command injection via the /goform/editFileName endpoint, allowing potential full system compromise.
date: "2026-08-23T05:35:21Z"
lastmod: "2026-08-23T23:39:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - command-injection
  - network-device
vendors:
  - Tenda
products:
  - CH22
  - CH22 (1.0.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument editNameMit results in command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument cmdinput leads to command injection.
    confidence_band: high
cves:
  - id: CVE-2026-78063
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78063
  - https://vuldb.com/cve/CVE-2026-78063
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78141
  - https://vuldb.com/vuln/394524
rules:
  - title: Detect CVE-2026-78063 Exploitation - Command Injection in Tenda CH22
    description: Detects exploitation attempts against CVE-2026-78063 where shell metacharacters are injected into the editNameMit parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-78141 Exploitation - Command Injection via /goform/exeCommand
    description: Detects attempts to exploit CVE-2026-78141 by identifying shell metacharacters in the cmdinput parameter sent to the /goform/exeCommand endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Tenda CH22 devices and restrict public internet access
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78063 requires mitigation for remote command injection
  hunt_leads:
    - lead: Search web logs for POST requests to /goform/editFileName
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint is directly associated with the injection vulnerability
  mitigation_plan:
    - priority: immediate
      action: Firmware update to version > 1.0.0.1 if available
      owner: IT Operations
      addresses: CVE-2026-78063
      evidence: Source identified version 1.0.0.1 as vulnerable
updates:
  - at: "2026-08-23T23:39:14Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-78141 Exploitation - Command Injection via /goform/exeCommand'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78141
---

A critical command injection vulnerability exists in Tenda CH22 firmware version 1.0.0.1, specifically within the function 'formeditFileName' located in the file '/goform/editFileName'. The vulnerability is triggered by the improper sanitization of the 'editNameMit' parameter, allowing an attacker to inject and execute arbitrary system commands. This flaw is remotely exploitable and proof-of-concept exploit code has been publicly released, increasing the risk of exploitation by threat actors. Given the nature of the device as a network routing component, successful exploitation provides an attacker with a persistent foothold, potential for traffic interception, and capability for lateral movement within the local network. 

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable Tenda CH22 devices via the public internet.
2. Attacker crafts a malicious HTTP POST request targeting the endpoint '/goform/editFileName'.
3. The request includes a payload within the 'editNameMit' parameter containing shell metacharacters (e.g., ;, |, &&).
4. The web server process of the Tenda firmware fails to sanitize the input before passing it to a system-level function.
5. The underlying operating system executes the injected command with the privileges of the web service process.
6. Attacker initiates a reverse shell connection or downloads additional post-exploitation tooling to maintain access.
7. Final objective achieved: unauthorized administrative control over the network device.

## Impact

Successful exploitation of this vulnerability results in full remote command execution on the target router. This allows an attacker to manipulate network traffic, bypass firewall rules, pivot to internal resources, or add the device to a botnet. As this is a networking appliance, the impact extends to all devices communicating through the compromised router.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:
- Identify and inventory all Tenda CH22 devices within the environment to assess exposure.
- Apply network segmentation to isolate these devices from the public internet.
- Monitor web traffic logs for HTTP POST requests targeting the '/goform/editFileName' URI.
- Implement the provided Sigma rule to detect exploitation attempts targeting the 'editNameMit' parameter.
- Check the Tenda support website for firmware updates addressing CVE-2026-78063 and patch all affected instances immediately.
