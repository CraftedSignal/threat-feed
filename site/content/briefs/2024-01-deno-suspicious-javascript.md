---
title: Suspicious JavaScript Execution via Deno
slug: 2024-01-deno-suspicious-javascript
description: This rule detects the execution of JavaScript via Deno with suspicious command-line patterns such as base64, eval, http, or javascript import, which attackers may abuse to run malicious JavaScript for execution or staging.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - javascript
  - deno
  - execution
vendors:
  - Deno
products:
  - Deno
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://reliaquest.com/blog/threat-spotlight-casting-a-wider-net-clickfix-deno-and-leaknets-scaling-threat
  - https://deno.com/
rules:
  - title: Detect Suspicious JavaScript Execution via Deno
    description: Detects execution of JavaScript via Deno with suspicious command-line patterns (base64, eval, http, or import in a javascript context).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Deno Execution by Original Filename
    description: Detects execution of Deno via original filename with suspicious command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Deno runtime environment, designed for JavaScript and TypeScript, can be abused by threat actors to execute malicious scripts. This detection focuses on identifying suspicious command-line arguments used with Deno, specifically those containing base64 encoding, eval, HTTP requests, or JavaScript imports. These patterns are often indicative of malicious intent, where attackers use Deno to stage or execute further attacks, download payloads, or run arbitrary code. This activity has been observed in campaigns like Clickfix and Leaknets, where Deno was used to scale their operations, as reported by Reliaquest.

## Attack Chain

1. An attacker gains initial access to a Windows system through an unknown vector (e.g., compromised software, remote service exploitation).
2. The attacker downloads the Deno runtime executable (`deno.exe`) to the compromised system.
3. The attacker executes `deno.exe` with a command line containing suspicious patterns such as `base64`, `eval()`, `http`, or `import`.
4. The Deno process interprets the malicious JavaScript code.
5. The JavaScript code performs malicious actions, such as downloading additional payloads from remote HTTP servers.
6. The downloaded payloads are executed, leading to further compromise of the system.
7. The attacker establishes persistence on the system.
8. The attacker performs lateral movement within the network to compromise additional systems and achieve their objectives (e.g., data theft, ransomware deployment).

## Impact

Successful exploitation can lead to arbitrary code execution, system compromise, and potentially lateral movement within the network. Depending on the malicious JavaScript's intent, the impact could range from data exfiltration to ransomware deployment. While the exact number of victims is unknown, the use of Deno in campaigns like Clickfix and Leaknets indicates the potential for widespread impact across various sectors.

## Recommendation

*   Enable Sysmon process creation logging to monitor process execution events (Data Source: Sysmon).
*   Deploy the Sigma rule "Detect Suspicious JavaScript Execution via Deno" to your SIEM to identify Deno processes with suspicious command-line arguments.
*   Implement application control policies to restrict the execution of unauthorized software, including Deno if it is not a standard tool in your environment.
*   Investigate and block any identified malicious domains or IPs used in the Deno command line (references).
