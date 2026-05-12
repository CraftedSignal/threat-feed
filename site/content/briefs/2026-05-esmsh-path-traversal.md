---
title: esm.sh Legacy Route Path Traversal Leads to Remote Code Execution
slug: 2026-05-esmsh-path-traversal
description: A path traversal vulnerability in esm.sh allows an attacker to write arbitrary files to the server leading to privilege escalation and potentially remote code execution via CVE-2026-44593.
date: "2026-05-12T22:24:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path traversal
  - remote code execution
  - cve-2026-44593
  - privilege escalation
vendors:
  - GitHub
products:
  - esm.sh
  - github.com/esm-dev/esm.sh
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Uncommonly Used File Binding
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-3636-h3vx-6465
rules:
  - title: Detect CVE-2026-44593 Exploitation -- Web Request with Path Traversal
    description: Detects CVE-2026-44593 exploitation -- HTTP requests containing path traversal sequences targeting the esm.sh server.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-44593 Exploitation -- Arbitrary File Write via Path Traversal
    description: Detects CVE-2026-44593 exploitation -- File creation events in unexpected directories resulting from path traversal exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical path traversal vulnerability, CVE-2026-44593, exists in esm.sh, potentially leading to remote code execution. Discovered by splitline from DEVCORE Research Team, the vulnerability allows an attacker to write arbitrary files to the server by exploiting insufficient path sanitization in the legacy router. The issue stems from the server's handling of crafted URLs containing path traversal sequences. By manipulating the request path, an attacker can bypass intended security measures and write data to locations outside the intended storage directory. This flaw impacts versions prior to commit 1960055e1d53 on May 8, 2026, and could be exploited to overwrite critical system files, ultimately granting the attacker elevated privileges and the ability to execute arbitrary code.

## Attack Chain

1. An attacker crafts a malicious URL containing path traversal sequences, such as `..%2f`, targeting the esm.sh server. An example: `http://ESM_SH_HOST/v111/react@19.2.0/esnext/..%2f..%2f..%2fgh/<attacker>/exp@1171e85d5d/foo.md%23%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2ftmp%2fpwned`
2. The esm.sh server receives the crafted request and forwards it to the legacy server.
3. The legacy server attempts to retrieve a file from a specified GitHub repository based on the URL. In the example, it attempts to fetch `foo.md` from `https://github.com/<attacker>/exp`.
4. The server constructs a storage path by concatenating the components of the request path without proper sanitization.
5. Path normalization occurs, resolving relative segments (e.g., `../../../`) in the constructed storage path, which can lead to writing to an arbitrary file path, like `/tmp/pwned`.
6. The content retrieved from the GitHub repository is written to the attacker-controlled file path on the esm.sh server.
7. The attacker repeats this process to overwrite critical binaries or scripts on the server.
8. Upon execution of the overwritten binaries/scripts, the attacker achieves remote code execution with the server's privileges.

## Impact

Successful exploitation allows attackers to write arbitrary files to the server. This can lead to privilege escalation by overwriting system binaries or scripts. The end result is remote code execution with the privileges of the esm.sh server process. While the exact number of victims is not specified, any esm.sh instance running a vulnerable version is susceptible to this attack.

## Recommendation

*   Upgrade the `go/github.com/esm-dev/esm.sh` package to a version equal to or greater than `0.0.0-20260508100112-1960055e1d53` to remediate CVE-2026-44593.
*   Deploy the Sigma rule "Detect CVE-2026-44593 Exploitation -- Web Request with Path Traversal" to detect attempts to exploit this vulnerability in web server logs.
*   Monitor web server logs for suspicious URL patterns containing path traversal sequences like `..%2f` and `../` in the request path, as these may indicate exploitation attempts.
