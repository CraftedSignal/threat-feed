---
title: GPT Researcher Code Injection Vulnerability (CVE-2026-5631)
slug: 2026-04-gpt-researcher-code-injection
description: A remote code injection vulnerability exists in assafelovic gpt-researcher versions up to 3.4.3 due to improper handling of the 'args' argument in the extract_command_data function, potentially allowing attackers to execute arbitrary code.
date: "2026-04-06T07:16:01Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - code-injection
  - vulnerability
  - gpt-researcher
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5631
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5631
  - https://github.com/assafelovic/gpt-researcher/
  - https://vuldb.com/vuln/355419
rules:
  - title: Detect GPT Researcher Code Injection Attempt via ws Endpoint
    description: Detects potential code injection attempts targeting the extract_command_data function in GPT Researcher via suspicious requests to the ws Endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect GPT Researcher Process Spawning from Web Server
    description: Detects unexpected process spawning from the web server process after CVE-2026-5631.
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

A code injection vulnerability, identified as CVE-2026-5631, affects assafelovic gpt-researcher up to version 3.4.3. The vulnerability resides in the `extract_command_data` function within the `backend/server/server_utils.py` file, specifically in the `ws Endpoint` component. By manipulating the `args` argument, a remote attacker can inject and execute arbitrary code on the affected system. Public exploit code is available, increasing the risk of exploitation. The maintainers of the `gpt-researcher` project have been notified of this vulnerability through an issue report, but have yet to respond. This vulnerability allows for unauthenticated remote code execution, severely impacting the confidentiality, integrity, and availability of the system.

## Attack Chain

1.  Attacker identifies a vulnerable instance of `gpt-researcher` running version 3.4.3 or earlier.
2.  The attacker crafts a malicious payload designed to exploit the `extract_command_data` function within `backend/server/server_utils.py`.
3.  The attacker sends a specially crafted request containing the malicious payload to the `ws Endpoint` via a remote connection.
4.  The `extract_command_data` function processes the attacker-supplied `args` without proper sanitization or validation.
5.  Due to the missing input validation, the malicious payload is interpreted as code.
6.  The injected code is executed within the context of the `gpt-researcher` application, potentially granting the attacker elevated privileges.
7.  The attacker establishes a reverse shell to gain persistent access to the server.
8.  The attacker compromises sensitive data or pivots to other systems on the network.

## Impact

Successful exploitation of CVE-2026-5631 allows a remote, unauthenticated attacker to execute arbitrary code on the server running the vulnerable `gpt-researcher` instance. The attacker can gain complete control of the affected system, potentially leading to data breaches, service disruption, or further lateral movement within the network. Given that `gpt-researcher` is often used in research or development environments, the compromise could result in the theft of sensitive intellectual property or research data. The ease of exploitation due to the availability of public exploits increases the likelihood of widespread attacks.

## Recommendation

*   Upgrade to a patched version of `gpt-researcher` as soon as one becomes available to remediate CVE-2026-5631.
*   Deploy the following Sigma rule to detect potential exploitation attempts targeting the `extract_command_data` function.
*   Monitor network traffic for suspicious requests to the `ws Endpoint` associated with `gpt-researcher` to identify potential exploitation attempts.
*   Implement input validation and sanitization measures within the `extract_command_data` function to prevent code injection, as suggested by CVE-2026-5631.
