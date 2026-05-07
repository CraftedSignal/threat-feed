---
title: Gotenberg Unauthenticated RCE via ExifTool Metadata Key Injection
slug: 2024-01-gotenberg-rce
description: Gotenberg version 8.29.1 is vulnerable to unauthenticated remote code execution (RCE) due to newline injection in metadata keys passed to ExifTool, allowing arbitrary command execution via the `-if` flag.
date: "2024-01-03T16:25:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - gotenberg
  - rce
  - exiftool
  - newline-injection
  - cwe-78
vendors:
  - Gotenberg
products:
  - Gotenberg 8.29.1
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-rqgh-gxv4-6657
rules:
  - title: Detect Gotenberg RCE Attempt via Metadata Key Injection
    description: Detects attempts to exploit the Gotenberg RCE vulnerability by identifying POST requests to the metadata write endpoint with newline characters in the metadata parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - rce
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Gotenberg RCE Attempt via Metadata Key Injection - Raw Newlines
    description: Detects attempts to exploit the Gotenberg RCE vulnerability by identifying POST requests to the metadata write endpoint with raw newline characters in the metadata parameter. This assumes raw logs are available before URL encoding.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - rce
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect ExifTool Command Execution via Process Monitoring
    description: Detects ExifTool executing system commands, indicative of command injection vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - execution
      - rce
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Gotenberg version 8.29.1, a popular Docker-based solution for converting documents to PDF, is vulnerable to unauthenticated remote code execution (RCE). The vulnerability resides in the `/forms/pdfengines/metadata/write` endpoint, which handles writing metadata to PDF files. Due to insufficient validation of JSON metadata keys, an attacker can inject newline characters (`\n`) to manipulate ExifTool arguments. This allows the attacker to inject the `-if` flag to execute arbitrary Perl code, leading to OS command execution. This vulnerability was discovered on 2026-04-04 and affects deployments where Gotenberg's port 3000 is exposed without authentication. Exploitation is straightforward, requiring a single HTTP POST request with a crafted JSON payload, and the server returns a 200 OK status with a valid PDF, obscuring the attack.

## Attack Chain

1. The attacker sends a POST request to `/forms/pdfengines/metadata/write` with a PDF file and a `metadata` JSON object.
2. The JSON object contains a key with embedded newline characters (`\n`).  For example: `"Title\\n-if\\nsystem('id')||1\\n-Comment": "x"`.
3. Gotenberg's backend deserializes the JSON object. The `\n` character is preserved.
4. The crafted key is passed to the go-exiftool library.
5. go-exiftool writes the key verbatim to ExifTool's stdin, splitting it into separate arguments: `-Title`, `-if`, `system('id')||1`, `-Comment=x`.
6. ExifTool executes the `system('id')` command due to the `-if` flag, which evaluates Perl expressions.
7. The attacker exfiltrates the command output via out-of-band techniques, such as an HTTP callback.
8. The server responds with HTTP 200 and a valid PDF file.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary commands as the Gotenberg process user, which is `gotenberg` (UID 1001) and a member of the `root` group in the default Docker image. This enables the attacker to read and write files, establish reverse shells, or pivot to other systems in the network. Because the vulnerability requires no authentication and provides no error signal, any Gotenberg instance exposed to an untrusted network is at risk of complete compromise.

## Recommendation

*   Implement input validation within Gotenberg to reject metadata keys containing control characters such as `\n`, `\r`, and `\x00`. Reference the code example in the advisory (strings.ContainsAny).
*   Deploy the following Sigma rule to detect exploitation attempts by identifying requests with newline characters in the metadata parameter.
*   Place Gotenberg behind an authenticated reverse proxy to prevent direct access from untrusted networks.
*   Monitor webserver logs for POST requests to the `/forms/pdfengines/metadata/write` endpoint, as this is the entry point for the attack. Enable webserver logging to capture request parameters.
