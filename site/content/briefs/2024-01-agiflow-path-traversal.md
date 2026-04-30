---
title: AgiFlow scaffold-mcp Path Traversal Vulnerability (CVE-2026-7237)
slug: 2024-01-agiflow-path-traversal
description: A path traversal vulnerability (CVE-2026-7237) exists in AgiFlow scaffold-mcp versions up to 1.0.27, allowing remote attackers to write to arbitrary files by manipulating the file_path argument in the write-to-file tool.
date: "2026-04-28T08:16:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - cve
  - web-application
vendors:
  - AgiFlow
products:
  - scaffold-mcp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-7237
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7237
rules:
  - title: Detect AgiFlow Scaffold-mcp Path Traversal Attempt
    description: Detects potential path traversal attempts targeting AgiFlow scaffold-mcp by looking for common path traversal sequences in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AgiFlow Scaffold-mcp Potential File Write via Path Traversal
    description: Detects potential file write attempts after a possible path traversal in AgiFlow scaffold-mcp. This focuses on POST requests to the vulnerable endpoint.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AgiFlow scaffold-mcp, a software component with unknown functionality, is vulnerable to a path traversal attack. This vulnerability, identified as CVE-2026-7237, affects versions up to 1.0.27. The vulnerability resides in the `packages/scaffold-mcp/src/server/index.ts` file, specifically within the "write-to-file" tool. An attacker can remotely exploit this flaw by manipulating the `file_path` argument, enabling them to write to arbitrary locations on the server. A patch has been released in version 1.1.0 with commit hash `c4d23592ae5fb59cfeefc4641e6826f8ac89b9c6` to address this vulnerability. The exploit is publicly available.

## Attack Chain

1.  The attacker identifies an AgiFlow scaffold-mcp instance running a vulnerable version (<= 1.0.27).
2.  The attacker crafts a malicious request targeting the "write-to-file" tool.
3.  The request includes a manipulated `file_path` argument containing path traversal sequences (e.g., "../", "..\\").
4.  The server-side application processes the request without proper sanitization or validation of the `file_path` argument.
5.  The application attempts to write data to the attacker-controlled file path.
6.  Due to the path traversal sequences, the data is written to an arbitrary location on the server's file system.
7.  The attacker may overwrite critical system files, inject malicious code, or exfiltrate sensitive data, depending on the write permissions and targeted file location.
8.  Successful exploitation leads to arbitrary code execution, data compromise, or denial of service.

## Impact

Successful exploitation of CVE-2026-7237 allows attackers to write arbitrary files to the affected system, potentially leading to code execution, data exfiltration, or denial of service. The number of affected installations is currently unknown. Due to the public availability of the exploit, organizations using AgiFlow scaffold-mcp are at immediate risk.

## Recommendation

*   Upgrade AgiFlow scaffold-mcp to version 1.1.0 or later to remediate CVE-2026-7237, applying the patch identified by commit hash `c4d23592ae5fb59cfeefc4641e6826f8ac89b9c6`.
*   Implement input validation and sanitization on the `file_path` argument within the "write-to-file" tool to prevent path traversal attacks.
*   Deploy the Sigma rule "Detect AgiFlow Scaffold-mcp Path Traversal Attempt" to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests containing path traversal sequences in the URI.
