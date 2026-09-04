---
title: Path Traversal Vulnerability in excel-mcp-server (CVE-2026-85661)
slug: 2026-09-excel-mcp-server-traversal
description: The excel-mcp-server package version 0.1.8 fails to enforce path confinement in stdio mode when EXCEL_FILES_PATH is unset, allowing attackers to perform arbitrary file reads and writes on the host system.
date: "2026-09-04T17:26:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:excel-mcp-server:excel-mcp-server:0.1.8:*:*:*:*:*:*:*
products:
  - excel-mcp-server (0.1.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565.001
    technique_name: Stored Data Manipulation
    evidence: An attacker can exploit this to perform arbitrary file reads and writes on the host system with the permissions of the process.
    confidence_band: high
cves:
  - id: CVE-2026-85661
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85661
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Set the EXCEL_FILES_PATH environment variable to a secure directory
      owner: IT Operations
      addresses: CVE-2026-85661
      evidence: Source states vulnerability occurs when EXCEL_FILES_PATH is unset
---

The excel-mcp-server package, specifically version 0.1.8, contains a critical path traversal vulnerability (CVE-2026-85661) arising from improper validation of file paths when the `EXCEL_FILES_PATH` environment variable is not explicitly configured in stdio mode. Because the application fails to enforce directory confinement under these conditions, it inadvertently allows any input provided to its file-related tools to resolve to arbitrary locations on the underlying host filesystem. An attacker capable of interacting with the server's MCP tools can exploit this to read sensitive configuration files, modify application data, or potentially write malicious payloads to system directories, effectively inheriting the permissions of the service process.

## Impact

Successful exploitation allows for full file system access within the context of the service user. This poses a significant risk of data exfiltration and persistent system compromise, particularly in environments where the service is running with elevated or overly permissive account privileges.

## Recommendation

* Immediately upgrade to a patched version of excel-mcp-server when available.
* Explicitly define the `EXCEL_FILES_PATH` environment variable in all deployments to restrict the service to a designated, hardened directory.
* Audit filesystem logs for unexpected file access patterns originating from the process executing the excel-mcp-server instance.
