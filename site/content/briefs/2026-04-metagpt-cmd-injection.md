---
title: MetaGPT Bash.run Command Injection Vulnerability (CVE-2026-5974)
slug: 2026-04-metagpt-cmd-injection
description: A command injection vulnerability exists in FoundationAgents MetaGPT version 0.8.1 affecting the Bash.run function, enabling remote attackers to execute arbitrary OS commands via crafted input.
date: "2026-04-09T20:16:29Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - command-injection
  - metagpt
  - cve-2026-5974
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5974
    cvss: 7.3
    epss: 0.01761
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5974
  - https://github.com/FoundationAgents/MetaGPT/
  - https://github.com/FoundationAgents/MetaGPT/issues/1931
  - https://github.com/FoundationAgents/MetaGPT/pull/1940
  - https://vuldb.com/submit/791758
  - https://vuldb.com/vuln/356528
  - https://vuldb.com/vuln/356528/cti
rules:
  - title: Detect Suspicious MetaGPT Bash.run Execution
    description: Detects suspicious process execution originating from MetaGPT's Bash.run function, indicative of command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Shell Command Execution via Python
    description: Detects shell command execution via python script
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

A critical command injection vulnerability, tracked as CVE-2026-5974, has been identified in FoundationAgents MetaGPT up to version 0.8.1. The vulnerability resides within the `Bash.run` function located in the `metagpt/tools/libs/terminal.py` library. An attacker can exploit this flaw by injecting malicious commands into the `Bash.run` function, leading to arbitrary OS command execution on the target system. The vulnerability is remotely exploitable, posing a significant risk. Although the developers were notified via a pull request, no patch has been released as of the publication of this brief. This vulnerability could be exploited to gain unauthorized access, escalate privileges, or compromise the entire system.

## Attack Chain

1.  An attacker identifies a MetaGPT instance running version 0.8.1 or earlier.
2.  The attacker crafts a malicious input string containing OS commands.
3.  This malicious string is passed to the `Bash.run` function in `metagpt/tools/libs/terminal.py`.
4.  Due to insufficient input validation, the injected commands are not properly neutralized.
5.  The `Bash.run` function executes the injected OS commands using the underlying operating system's shell.
6.  The attacker gains the ability to execute arbitrary code on the server.
7.  The attacker could then install malware, create new user accounts, or exfiltrate sensitive data.

## Impact

Successful exploitation of this vulnerability could allow an attacker to execute arbitrary operating system commands on the server hosting the vulnerable MetaGPT instance. This could lead to complete system compromise, including data theft, malware installation, and denial-of-service attacks. Due to the nature of command injection, the impact is highly dependent on the privileges of the user account running the MetaGPT application.

## Recommendation

*   Apply input validation and sanitization to the `Bash.run` function in the `metagpt/tools/libs/terminal.py` library to prevent command injection (CVE-2026-5974).
*   Monitor process creations for unusual commands executed by the MetaGPT application (see Sigma rule "Detect Suspicious MetaGPT Bash.run Execution").
*   Deploy a web application firewall (WAF) to filter out potentially malicious payloads being sent to the MetaGPT application.
