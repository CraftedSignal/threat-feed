---
title: Vitest Arbitrary File Read Vulnerability
slug: 2026-06-vitest-file-read
description: An arbitrary file read vulnerability exists in Vitest when the UI server is listening, especially when exposed to the network, allowing an attacker to read arbitrary files outside the project directory and potentially execute arbitrary scripts.
date: "2026-06-01T14:15:03Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - arbitrary-file-read
  - code-execution
  - vitest
  - cve-2026-47429
vendors:
  - Vitest
products:
  - vitest (< 4.1.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-5xrq-8626-4rwp
rules:
  - title: Detect CVE-2026-47429 Exploitation - Vitest Arbitrary File Read Attempt
    description: Detects CVE-2026-47429 exploitation - suspicious requests to the `/__vitest_attachment__` endpoint with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Vitest Process Spawning Suspicious Processes
    description: Detects Vitest process spawning suspicious processes, which may indicate command execution due to CVE-2026-47429.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical vulnerability exists in Vitest versions prior to 4.1.0 that allows arbitrary file reads on Windows systems when the Vitest UI server is active, particularly if exposed to the network. The flaw stems from the incorrect usage of the deprecated `isFileServingAllowed` function within the `/__vitest_attachment__` API handler. By using the `\\?\\..\\` path traversal technique, attackers can bypass intended security checks and access files outside the project directory. This vulnerability, identified as CVE-2026-47429, could also lead to arbitrary script execution due to the API's rerun and file write capabilities. To mitigate this, Vitest now includes `allowWrite` and `allowExec` configuration flags, which are disabled by default when the API server is bound to a non-localhost host.

## Attack Chain

1.  Attacker identifies a vulnerable Vitest instance with its UI server exposed to the network, running on a Windows system.
2.  Attacker obtains the API token by sending a request to `http://localhost:51204/__vitest__/`.
3.  Attacker crafts a malicious request to the `/__vitest_attachment__` endpoint with a path traversal payload: `http://localhost:51204/__vitest_attachment__?path=C:\\path\\to\\project\\?\\..\\..\\secret.txt&contentType=text/plain&token=$TOKEN`.
4.  The `isFileServingAllowed` check is bypassed due to the use of the `\\?\\..\\` sequence.
5.  The Vitest server reads the content of the specified file (`secret.txt`) outside the intended project directory.
6.  The attacker receives the content of the file in the response.
7.  Attacker leverages the API's rerun feature and file write feature (`saveTestFile`) to write a malicious test file containing arbitrary code.
8.  Attacker uses the rerun feature to execute the newly created test file, achieving arbitrary script execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the affected system. If the attacker is able to read sensitive files containing credentials or configuration data, it could lead to further compromise of the system or network. The ability to execute arbitrary scripts allows for full system compromise, data exfiltration, or denial-of-service attacks. This vulnerability affects any Vitest instances with UI server exposed to network and running on Windows prior to version 4.1.0

## Recommendation

*   Upgrade Vitest to version 4.1.0 or later to patch CVE-2026-47429.
*   Ensure that the `allowWrite` and `allowExec` configuration flags are disabled when the Vitest API server is bound to a non-localhost host as per the vendor mitigations.
*   Monitor network traffic for suspicious requests to the `/__vitest_attachment__` endpoint with path traversal sequences using the Sigma rule provided below.
*   Monitor process creation for unexpected script execution originating from the Vitest process using the provided Sigma rule.
