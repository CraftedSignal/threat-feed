---
title: MetaGPT OS Command Injection Vulnerability (CVE-2026-5972)
slug: 2026-04-metagpt-command-injection
description: A remote command injection vulnerability exists in FoundationAgents MetaGPT <= 0.8.1 via the Terminal.run_command function, allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2026-04-09T20:16:28Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-5972
  - command-injection
  - metagpt
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5972
    cvss: 7.3
    epss: 0.01761
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5972
  - https://github.com/FoundationAgents/MetaGPT/
  - https://github.com/FoundationAgents/MetaGPT/issues/1929
  - https://github.com/paipeline/MetaGPT/commit/d04ffc8dc67903e8b327f78ec121df5e190ffc7b
  - https://vuldb.com/submit/791745
  - https://vuldb.com/vuln/356526
  - https://vuldb.com/vuln/356526/cti
rules:
  - title: Detect Command Execution via MetaGPT
    description: Detects command execution originating from the MetaGPT application, which could indicate command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connection from MetaGPT
    description: Detects outbound network connections originating from the MetaGPT application to suspicious IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-5972 describes a critical OS command injection vulnerability affecting FoundationAgents MetaGPT versions up to 0.8.1. The vulnerability resides in the `Terminal.run_command` function within the `metagpt/tools/libs/terminal.py` file. This flaw allows remote attackers to inject and execute arbitrary operating system commands on the affected system. The vulnerability is remotely exploitable, meaning that attackers can trigger it over a network without requiring local access. Public exploits for this vulnerability are available, increasing the risk of widespread exploitation. The patch identified as `d04ffc8dc67903e8b327f78ec121df5e190ffc7b` addresses this vulnerability and upgrading to a patched version is highly recommended.

## Attack Chain

1.  An attacker identifies a vulnerable MetaGPT instance running a version <= 0.8.1.
2.  The attacker crafts a malicious request targeting the `Terminal.run_command` function.
3.  The malicious request contains an OS command injection payload within the input parameters expected by `Terminal.run_command`.
4.  MetaGPT processes the request, passing the attacker-controlled input to the underlying operating system's command interpreter without proper sanitization.
5.  The operating system executes the injected command as part of the MetaGPT process, granting the attacker code execution within the server environment.
6.  The attacker leverages the initial foothold to escalate privileges, potentially gaining root access or compromising other services on the system.
7.  The attacker may then install malware, establish persistence, or exfiltrate sensitive data.
8.  The attacker achieves their final objective, which could include data theft, denial of service, or complete system compromise.

## Impact

Successful exploitation of this vulnerability allows remote attackers to execute arbitrary commands on the affected system. This can lead to complete system compromise, including data theft, malware installation, and denial of service. Given the publicly available exploit, unpatched MetaGPT instances are at immediate risk. The vulnerability has a CVSS v3.1 score of 7.3, indicating a high level of severity. The number of victims and sectors targeted is currently unknown, but given the nature of the vulnerability, any organization using MetaGPT is potentially at risk.

## Recommendation

*   Apply the patch `d04ffc8dc67903e8b327f78ec121df5e190ffc7b` provided by FoundationAgents to remediate the vulnerability.
*   Monitor web server logs for suspicious requests targeting the MetaGPT application, specifically those containing command injection attempts (cs-uri-query, cs-method, sc-status).
*   Implement the provided Sigma rule to detect command execution originating from the MetaGPT application (logsource).
*   Review network traffic for unusual outbound connections originating from MetaGPT servers, which could indicate successful exploitation and malware installation (category: network_connection).
*   Enable and review process creation logs on MetaGPT servers to identify any unexpected child processes spawned by the MetaGPT application, as this could indicate command injection exploitation (category: process_creation).
