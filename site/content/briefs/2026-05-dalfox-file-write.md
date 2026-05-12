---
title: Dalfox Server Mode Unauthenticated Arbitrary File Create/Append Vulnerability
slug: 2026-05-dalfox-file-write
description: Dalfox in REST API server mode is vulnerable to CVE-2026-45089, an unauthenticated arbitrary file create/append vulnerability, due to the `output`, `output-all`, and `debug` options being deserialized directly from the attacker's request body, allowing a network caller to create or append to any file writable by the dalfox process.
date: "2026-05-12T15:10:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - file-write
  - unauthenticated
  - CVE-2026-45089
vendors:
  - hahwul
products:
  - dalfox <= 2.12.0
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-8hf9-3q64-q2qf
  - CVE-2026-45089
rules:
  - title: Detect Dalfox Unauthenticated File Write Attempt
    description: Detects CVE-2026-45089 exploitation — POST requests to /scan with 'output' parameter indicating potential arbitrary file write.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Dalfox File Write via Output Parameter
    description: Detects CVE-2026-45089 exploitation — Creates file via output parameter. The process writing is dalfox.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Dalfox, a cross-platform vulnerability scanner, is susceptible to an unauthenticated arbitrary file create/append vulnerability (CVE-2026-45089) when run in REST API server mode. This vulnerability stems from the insecure handling of the `output`, `output-all`, and `debug` fields within the `model.Options` struct. These fields are directly deserialized from the JSON request body of an attacker without proper sanitization, and then propagated into the scan engine's logging path. Consequently, an attacker can create or append to any file on the host filesystem accessible to the dalfox process by sending a crafted POST request to the `/scan` endpoint. The default configuration lacks API key authentication, compounding the risk. This affects dalfox versions 2.12.0 and earlier.

## Attack Chain

1. An attacker sends a POST request to the `/scan` endpoint of the dalfox REST API server.
2. The request body contains a JSON object with the `url` field set to the scan target and the `options` field containing attacker-controlled values for `output`, `output-all`, and `debug`.
3. The `postScanHandler` function binds the JSON request body to a `Req` struct, which includes the `Options` field of type `model.Options`.
4. The `ScanFromAPI` function is called with the attacker-supplied `URL` and `Options` values.
5. The `Initialize` function copies the attacker-controlled `OutputFile`, `OutputAll`, and `Debug` values from the `Options` struct into a new `newOptions` struct.
6. The `DalLog` function is called to write log messages. Critically, the file write operation using `os.OpenFile(options.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)` occurs outside the `IsLibrary` check.
7. The attacker-specified file path is opened in append mode, and log messages are written to it. The URL parameter is also written verbatim in the logs, allowing partial content control.
8. The attacker achieves arbitrary file creation or append on the dalfox host, leading to potential system compromise.

## Impact

Successful exploitation allows an attacker to create new files or append data to existing files on the dalfox host, provided the dalfox process has the necessary write permissions. This can lead to various impacts, including: arbitrary file creation (e.g., creating web shells in web-serving directories), arbitrary file append/corruption (e.g., corrupting application configuration files or cron entries), and potential remote code execution if the attacker can inject malicious content into a configuration file or script that is subsequently executed. The lack of authentication by default increases the severity, as any network-accessible dalfox instance is vulnerable.

## Recommendation

- Deploy the Sigma rule `Detect Dalfox Unauthenticated File Write Attempt` to identify attempts to exploit this vulnerability by monitoring for POST requests to the /scan endpoint with suspicious `output` parameters.
- Apply the recommended remediation by nullifying filesystem-dangerous fields from API-sourced requests in the `postScanHandler` function as outlined in the advisory. This includes setting `rq.Options.OutputFile = ""` before calling `ScanFromAPI`.
- As a defense-in-depth measure, guard the file write operation with `IsLibrary` in the `DalLog` function, ensuring that file writes only occur in non-library (CLI) mode.
- Enforce the use of the `--api-key` option at server startup, making authentication mandatory for the REST API server.
- Upgrade to a patched version of dalfox that incorporates these security fixes.
