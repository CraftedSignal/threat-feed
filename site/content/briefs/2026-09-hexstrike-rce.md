---
title: Remote Command Injection in 0x4m4 HexStrike AI
slug: 2026-09-hexstrike-rce
description: A command injection vulnerability in HexStrike AI allows remote unauthenticated attackers to execute arbitrary OS commands via the Execute Endpoint.
date: "2026-09-14T03:29:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:0x4m4:hexstrike_ai:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - command-injection
vendors:
  - 0x4m4
products:
  - HexStrike AI (<= d689933ff579d839c676c82b231f8e98326c5f04)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument code/script leads to os command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90619
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90619
rules:
  - title: Detects CVE-2026-90619 Exploitation - Remote OS Command Injection
    description: Detects HTTP requests to HexStrike AI containing shell metacharacters in the code or script arguments.
    platform: sigma
    severity: high
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy webserver detection rule to identify attempted exploitation
      owner: Detection Engineering
      due: 24h
      evidence: Public exploit exists and threat is remotely reachable
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the HexStrike AI Execute Endpoint
      owner: IT Operations
      addresses: CVE-2026-90619
      evidence: Vulnerability allows unauthenticated remote command injection
---

HexStrike AI, an open-source project by 0x4m4, contains a remote code execution vulnerability (CVE-2026-90619) affecting all releases up to commit d689933ff579d839c676c82b231f8e98326c5f04. The flaw resides within the 'Execute Endpoint' component inside the 'hexstrike_server.py' file. An attacker can trigger this vulnerability by sending a maliciously crafted request to the application, specifically targeting the 'code' or 'script' arguments. Because the input is processed without adequate sanitization, the application passes the user-supplied data directly to the underlying operating system's shell, resulting in arbitrary command execution. This vulnerability is remotely exploitable without authentication, and public proof-of-concept exploits exist, posing a high risk to organizations utilizing this component in production environments. As the project follows a continuous delivery model without versioned releases, users must monitor the project repository for updates.

## Impact

The vulnerability allows full remote code execution on the server hosting the HexStrike AI component. Successful exploitation leads to total system compromise, including potential data exfiltration, deployment of malicious payloads, or use of the server as a pivot point within the network. Because the vulnerability is remotely reachable and requires no authentication, it is highly attractive for opportunistic exploitation across any publicly exposed instances.

## Recommendation

1. Identify all instances of the HexStrike AI project within the environment and restrict network access to the 'Execute Endpoint' component until a patch is available.
2. Implement an application firewall or proxy-level filter to inspect incoming HTTP requests for suspicious shell metacharacters in the 'code' or 'script' query parameters.
3. Monitor webserver logs for requests directed at the Execute Endpoint containing patterns indicative of command injection (e.g., semicolons, pipe operators, or backticks).
4. Monitor process creation events on servers running HexStrike AI for unusual child processes (e.g., cmd.exe, /bin/sh, nc) spawned by the server process.
