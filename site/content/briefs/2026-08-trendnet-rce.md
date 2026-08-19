---
title: Command Injection in TRENDnet TEW-823DRU
slug: 2026-08-trendnet-rce
description: A command injection vulnerability in TRENDnet TEW-823DRU firmware 1.1.02b01 allows authenticated remote attackers to execute arbitrary commands via the Hostname parameter.
date: "2026-08-19T02:58:01Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TRENDnet
products:
  - TEW-823DRU (1.1.02b01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument Hostname results in command injection.
    confidence_band: high
cves:
  - id: CVE-2026-75984
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75984
  - https://vuldb.com/vuln/391903
rules:
  - title: Detects CVE-2026-75984 Exploitation - Command Injection in admin.cgi
    description: Detects attempts to exploit CVE-2026-75984 by identifying shell metacharacters in the Hostname parameter sent to the administrative CGI script.
    platform: sigma
    severity: high
    tactics:
      - execution
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
    - action: Review perimeter logs for indicators of /cgi-bin/admin.cgi access.
      owner: SOC
      due: 24h
      evidence: Source document identifies the vulnerable endpoint.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to administrative interfaces.
      owner: IT Operations
      addresses: CVE-2026-75984
      evidence: Remote vulnerability requires network-level access control.
---

A command injection vulnerability (CVE-2026-75984) exists in the TRENDnet TEW-823DRU router, specifically within the /cgi-bin/admin.cgi script. An authenticated remote attacker can manipulate the 'Hostname' argument to achieve arbitrary command execution on the underlying operating system. This vulnerability has been assigned a CVSS 3.1 base score of 7.4. Publicly available proof-of-concept (PoC) exploit code has been published, increasing the risk of exploitation by threat actors targeting small office/home office (SOHO) network infrastructure.

## Attack Chain

1. Attacker establishes network connectivity to the targeted TRENDnet router management interface.
2. Attacker authenticates to the device using valid credentials or exploits secondary credential weaknesses.
3. Attacker sends a crafted HTTP POST request targeting the /cgi-bin/admin.cgi endpoint.
4. Attacker inserts shell metacharacters into the 'Hostname' parameter value.
5. The web server process fails to sanitize the input before passing it to a system-level execution function.
6. The router executes the injected commands with the privileges of the web service.
7. Attacker establishes persistence or pivots further into the local network through the compromised device.

## Impact

Successful exploitation allows an attacker to gain remote code execution on the router, which can be leveraged for unauthorized network access, traffic interception, or the deployment of additional malicious payloads. As a core networking device, the compromise of a router can facilitate persistent access to internal network segments, potentially impacting all connected users and devices.

## Recommendation

- Immediately restrict access to the management interface of the TRENDnet TEW-823DRU to trusted internal management subnets only.
- Audit network logs for HTTP POST requests to /cgi-bin/admin.cgi containing shell metacharacters such as semicolon, pipe, or backtick in the 'Hostname' parameter.
- Verify device firmware and contact the vendor for available security patches or configuration guidance to mitigate CWE-77.
