---
title: Arbitrary File Read Vulnerability in mcp-atlassian
slug: 2026-09-mcp-atlassian-path-traversal
description: The mcp-atlassian package contains a path traversal vulnerability allowing an authenticated MCP caller to exfiltrate arbitrary server-local files to Jira or Confluence via attachment upload tools.
date: "2026-09-23T07:55:16Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - path-traversal
  - data-exfiltration
  - mcp
  - cve-2026-77253
products:
  - mcp-atlassian (< 0.22.0)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: An MCP caller who can invoke write tools can cause the server to read any file accessible to the MCP process and send it to Jira/Confluence as an attachment.
    confidence_band: high
cves:
  - id: CVE-2026-77253
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-vc25-24vv-fxxm
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade mcp-atlassian package to 0.22.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source states package is vulnerable < 0.22.0
  mitigation_plan:
    - priority: immediate
      action: Set READ_ONLY_MODE=true for all MCP instances
      owner: Security Engineering
      addresses: CVE-2026-77253
      evidence: Source states READ_ONLY_MODE=true blocks the vulnerable write tools
---

The mcp-atlassian package (prior to version 0.22.0) is vulnerable to an arbitrary file read vulnerability (CVE-2026-77253) due to a lack of path validation in its Jira and Confluence attachment upload tools. When an MCP server is deployed in a multi-user or HTTP-exposed environment, an attacker with write-tool access can trigger the upload of arbitrary local files accessible to the MCP process. The tools receive a 'file_path' parameter, perform minimal existence checks, and directly open the file for reading before transmitting it to the configured Jira or Confluence instance as an attachment. This vulnerability potentially allows for the exfiltration of sensitive server-side assets, including environment variables, service account credentials, mounted secrets, and source code. Defenders should immediately audit MCP deployments for exposure and upgrade to version 0.22.0 or later, which introduces necessary path validation logic.

## Attack Chain

1. The MCP server is deployed with HTTP access enabled, allowing remote interaction with its defined toolset.
2. An attacker identifies the 'upload_attachment' (Confluence) or 'update_issue' (Jira) tool within the mcp-atlassian configuration.
3. The attacker crafts a request to the MCP server invoking the write-capable attachment tool.
4. The attacker provides a target local file path (e.g., '/etc/passwd' or a local secret file) as the 'file_path' or 'attachments' argument.
5. The mcp-atlassian library receives the path and fails to invoke 'validate_safe_path()' or verify the file against an allowed directory list.
6. The server process opens the specified file using Python's 'open(file_path, "rb")'.
7. The process reads the file contents and transmits them as an attachment to the Jira issue or Confluence page associated with the authenticated user.
8. The attacker retrieves the exfiltrated sensitive content from the Jira or Confluence instance.

## Impact

Successful exploitation allows for unauthorized exfiltration of sensitive local data to enterprise issue tracking systems. This represents a significant risk in containerized or cloud-hosted environments where MCP servers may have access to mounted secrets, Kubernetes service account tokens, or local configuration files. Depending on the server's permissions, an attacker could extract credentials to pivot into deeper infrastructure or exfiltrate intellectual property via Jira and Confluence attachments.

## Recommendation

1. Upgrade the 'mcp-atlassian' package to version 0.22.0 or later immediately to resolve CVE-2026-77253.
2. If an immediate upgrade is not possible, enable 'READ_ONLY_MODE=true' on all MCP server instances to prevent the invocation of vulnerable write tools.
3. Implement strict network access controls for MCP servers exposed over HTTP; restrict access to authorized users or service identities only.
4. Conduct a review of file system permissions for the user account running the MCP server process to minimize the impact of potential path traversal, ensuring it cannot read sensitive configuration or secret files.
5. Audit Jira and Confluence audit logs for anomalous attachment uploads from the MCP-associated service account.
