---
title: MiroFish Command Injection Vulnerability (CVE-2026-7058)
slug: 2024-01-03-mirofish-command-injection
description: A command injection vulnerability exists in 666ghj MiroFish version 0.1.2 via the SimulationIPCClient.send_command function, allowing remote attackers to execute arbitrary commands.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - ipc
products:
  - MiroFish
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2026-7058
    cvss: 7.3
    epss: 0.01039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7058
rules:
  - title: Detect MiroFish Command Injection Attempt via URL
    description: Detects potential attempts to exploit the MiroFish command injection vulnerability by monitoring requests to the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - webserver
      - linux
  - title: Detect MiroFish Command Injection Attempt via POST Data
    description: Detects potential attempts to exploit the MiroFish command injection vulnerability by monitoring POST requests to the vulnerable endpoint with suspicious characters in the request body.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-7058, affects 666ghj MiroFish up to version 0.1.2. The vulnerability resides in the `SimulationIPCClient.send_command` function within the `backend/app/services/simulation_ipc.py` file, specifically within the Inter-Process Communication component. This flaw allows a remote attacker to inject and execute arbitrary commands on the system. Public disclosure of the exploit exists, increasing the risk of exploitation. The vendor was notified, but has not yet responded. This vulnerability poses a significant risk as it allows for complete system compromise.

## Attack Chain

1.  Attacker identifies a vulnerable MiroFish instance running version 0.1.2 or earlier.
2.  Attacker crafts a malicious command injection payload.
3.  Attacker sends a request to the `SimulationIPCClient.send_command` function via the Inter-Process Communication mechanism.
4.  The vulnerable function `SimulationIPCClient.send_command` fails to properly sanitize the attacker-supplied input.
5.  The unsanitized input is passed to a system call.
6.  The system executes the injected command with the privileges of the MiroFish process.
7.  The attacker gains arbitrary code execution on the server.
8.  The attacker can then perform actions such as installing malware, exfiltrating data, or pivoting to other systems on the network.

## Impact

Successful exploitation of this command injection vulnerability (CVE-2026-7058) allows an attacker to execute arbitrary commands on the affected system. This could lead to complete system compromise, data breaches, denial of service, or further lateral movement within the network. Given the public availability of the exploit, organizations using MiroFish 0.1.2 or earlier are at high risk.

## Recommendation

*   Apply appropriate input validation and sanitization to the `SimulationIPCClient.send_command` function to prevent command injection.
*   Monitor web server logs for suspicious requests targeting the `backend/app/services/simulation_ipc.py` endpoint (see rules below).
*   Deploy the Sigma rules provided to detect potential exploitation attempts.
