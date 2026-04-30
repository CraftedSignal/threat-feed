---
title: Path Traversal Vulnerability in engineer-your-data
slug: 2026-04-engineer-your-data-path-traversal
description: A path traversal vulnerability (CVE-2026-7214) exists in eghuzefa's engineer-your-data up to version 0.1.3, allowing remote attackers to read or write arbitrary files by manipulating the WORKSPACE_PATH argument.
date: "2026-04-28T02:16:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
vendors:
  - eghuzefa
products:
  - engineer-your-data (<= 0.1.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7214
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7214
rules:
  - title: Detect Engineer-Your-Data Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-7214) in engineer-your-data by identifying requests with path traversal sequences in the WORKSPACE_PATH parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Engineer-Your-Data File Access via Traversal
    description: Detects file access attempts resulting from path traversal in engineer-your-data by monitoring for file access events with unusual paths.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7214, has been discovered in eghuzefa's engineer-your-data, specifically affecting versions up to 0.1.3. This flaw resides within the `read_file`, `write_file`, `list_files`, and `file_inf` functions of the `src/server.py` file. Successful exploitation allows a remote attacker to bypass directory restrictions and access or modify files outside the intended `WORKSPACE_PATH`. The vulnerability's ease of exploitation is increased by the public availability of exploit code. Although the project was notified through an issue report, no response or patch has been released to date. This poses a significant risk to systems running vulnerable versions of engineer-your-data, potentially leading to sensitive data exposure or unauthorized modifications.

## Attack Chain

1.  The attacker identifies a vulnerable instance of `engineer-your-data` running version 0.1.3 or earlier.
2.  The attacker crafts a malicious request targeting the `read_file`, `write_file`, `list_files`, or `file_inf` endpoints.
3.  The malicious request includes a manipulated `WORKSPACE_PATH` argument containing path traversal sequences (e.g., `../`).
4.  The `src/server.py` script processes the request without proper sanitization or validation of the `WORKSPACE_PATH`.
5.  The application attempts to access a file system resource based on the attacker-controlled path.
6.  Due to the path traversal, the application accesses a file or directory outside the intended `WORKSPACE_PATH`.
7.  If the `read_file` function is targeted, the attacker retrieves the contents of an arbitrary file.
8.  If the `write_file` function is targeted, the attacker can overwrite an arbitrary file.

## Impact

Successful exploitation of this vulnerability allows a remote, unauthenticated attacker to read sensitive files on the server, potentially exposing credentials, configuration files, or other confidential data. Alternatively, an attacker could overwrite system files, leading to denial of service or arbitrary code execution. Given the public availability of exploit code, vulnerable systems are at high risk of compromise. The impact is amplified by the lack of a patch or response from the project maintainers.

## Recommendation

*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., "../") in the `WORKSPACE_PATH` parameter, as described in the attack chain. Deploy the Sigma rule `Detect Engineer-Your-Data Path Traversal Attempt` to identify malicious requests.
*   Apply input validation and sanitization to the `WORKSPACE_PATH` argument in `src/server.py` to prevent path traversal, addressing CVE-2026-7214.
*   Consider using a web application firewall (WAF) to block requests containing path traversal sequences.
