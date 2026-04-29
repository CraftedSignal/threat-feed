---
title: mcp-dnstwist OS Command Injection Vulnerability (CVE-2026-7443)
slug: 2024-01-03-mcp-dnstwist-command-injection
description: An OS command injection vulnerability exists in BurtTheCoder's mcp-dnstwist version 1.0.4 and earlier due to improper handling of the Request argument in the fuzz_domain function within src/index.ts, potentially allowing remote attackers to execute arbitrary commands.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - command-injection
  - vulnerability
vendors:
  - BurtTheCoder
products:
  - mcp-dnstwist
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7443
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7443
rules:
  - title: Detect Suspicious mcp-dnstwist Requests
    description: Detects potentially malicious HTTP requests targeting mcp-dnstwist servers that may indicate command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect mcp-dnstwist Process Spawning Suspicious Child Processes
    description: Detects mcp-dnstwist spawning shell processes, which could indicate command injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-7443 describes an OS command injection vulnerability affecting BurtTheCoder's mcp-dnstwist, a tool potentially used for detecting and preventing typosquatting attacks. The vulnerability resides in versions up to 1.0.4. The affected function, `fuzz_domain`, located in the `src/index.ts` file of the MCP Interface component, is susceptible to command injection. An attacker can manipulate the Request argument to inject arbitrary OS commands. This is a remotely exploitable vulnerability, meaning an attacker can trigger it over a network connection. Public exploits are available, increasing the risk of widespread exploitation. The vulnerability was reported to the project maintainers, but no response or patch has been released as of this writing.

## Attack Chain

1.  The attacker identifies a vulnerable instance of mcp-dnstwist running version 1.0.4 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the MCP Interface component.
3.  The crafted request includes a payload designed to exploit the `fuzz_domain` function in `src/index.ts`.
4.  The malicious payload manipulates the Request argument, injecting OS commands.
5.  The `fuzz_domain` function, without proper sanitization, executes the injected OS commands.
6.  The attacker gains arbitrary code execution on the server hosting mcp-dnstwist.
7.  The attacker leverages the initial access to escalate privileges or move laterally within the network.
8.  The attacker achieves their final objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary OS commands on the system hosting mcp-dnstwist. This could lead to complete system compromise, data breaches, or denial-of-service conditions. Given that mcp-dnstwist might be used in security-sensitive environments, a successful attack could have significant impact. The lack of a patch and the availability of public exploits increase the likelihood of exploitation.

## Recommendation

*   Since no patch is available, immediately discontinue use of mcp-dnstwist versions up to 1.0.4.
*   Monitor network traffic for suspicious requests targeting mcp-dnstwist instances by deploying the Sigma rule `Detect Suspicious mcp-dnstwist Requests` to your SIEM.
*   If continued use is unavoidable, implement strict input validation and sanitization on the Request argument passed to the `fuzz_domain` function in `src/index.ts`. However, this is not a substitute for patching the underlying vulnerability.
