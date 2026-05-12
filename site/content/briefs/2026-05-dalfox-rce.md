---
title: Dalfox Server Mode Vulnerable to Unauthenticated Remote Code Execution via `found-action`
slug: 2026-05-dalfox-rce
description: Dalfox in REST API server mode is vulnerable to unauthenticated remote code execution (CVE-2026-45087) because the server binds to 0.0.0.0:6664 by default without requiring an API key and deserializes attacker-supplied JSON in `POST /scan` without stripping the `FoundAction` and `FoundActionShell` fields, allowing arbitrary command execution.
date: "2026-05-12T15:10:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - dalfox
  - cve-2026-45087
vendors:
  - Hahwul
products:
  - dalfox/v2 (<= 2.12.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-v25v-m36w-jp4h
rules:
  - title: Detect CVE-2026-45087 Exploitation — Dalfox Scan POST Request with Found Action
    description: Detects CVE-2026-45087 exploitation — An HTTP POST request to /scan with found-action and found-action-shell parameters, indicating a command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-45087 Exploitation — Dalfox Found Action Command Execution
    description: Detects CVE-2026-45087 exploitation — Command execution with a parent process indicating Dalfox command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Dalfox, a security auditing tool, is vulnerable to unauthenticated remote code execution (CVE-2026-45087) when running in REST API server mode (`dalfox server`) with default settings. The server binds to `0.0.0.0:6664` and, unless explicitly configured with `--api-key`, does not require authentication. A flaw exists in how the server handles `model.Options`, specifically `FoundAction` and `FoundActionShell`, which are deserialized directly from attacker-supplied JSON in `POST /scan`. Because `dalfox.Initialize` propagates these fields into the final scan options without sanitization, any unauthenticated attacker can execute arbitrary shell commands on the host OS whenever a scan finding is triggered. This vulnerability affects dalfox versions 2.12.0 and earlier.

## Attack Chain

1. The attacker starts a `dalfox server` instance in REST API mode without specifying an API key, leaving it open to unauthenticated access.
2. The attacker sets up a malicious web server that reflects input, ensuring any scan against it will produce a finding.
3. The attacker crafts a `POST` request to the `/scan` endpoint of the dalfox server.
4. The request includes a JSON payload containing the URL of the malicious web server and `options` with malicious values for `found-action` and `found-action-shell`.
5. The `postScanHandler` deserializes the JSON payload into a `Req` struct, including the `options` field which contains the malicious `FoundAction` and `FoundActionShell` values.
6. The `ScanFromAPI` function is called, passing the attacker-controlled options to `dalfox.Initialize`.
7. `dalfox.Initialize` copies the attacker-supplied `FoundAction` and `FoundActionShell` values into the scan options without sanitization.
8. When a finding is triggered during the scan, the `foundAction` function executes the attacker-supplied shell command using `exec.Command`, achieving remote code execution on the dalfox host.

## Impact

Successful exploitation results in unauthenticated remote code execution on the host running `dalfox server`. This grants the attacker full read access to secrets, configuration files, and credentials accessible to the dalfox process. The attacker can perform arbitrary file writes, enabling persistence, backdoor installation, and data exfiltration. The default `0.0.0.0` bind address exposes the server to all network interfaces, potentially including public-facing ones in misconfigured environments.

## Recommendation

- **Require API key:** Enforce the use of `--api-key` in REST server mode by rejecting server startup if no API key is provided, as described in the remediation suggestion within the advisory.
- **Strip `FoundAction` / `FoundActionShell`:** Sanitize API-sourced requests by removing the `FoundAction` and `FoundActionShell` options in the `postScanHandler` to prevent untrusted callers from setting execution-control options.
- **Deploy the Sigma rules:** Deploy the provided Sigma rules to your SIEM and tune them for your environment to detect exploitation attempts.
- **Upgrade Dalfox:** Upgrade to a patched version of Dalfox that addresses CVE-2026-45087.
