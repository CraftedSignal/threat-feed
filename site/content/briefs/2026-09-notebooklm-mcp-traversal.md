---
title: Path Traversal Vulnerability in notebooklm-mcp
slug: 2026-09-notebooklm-mcp-traversal
description: The @roomi-fields/notebooklm-mcp package is vulnerable to arbitrary file write via path traversal in the vault_batch tool and /batch-to-vault endpoint, allowing attackers to plant malicious files in unauthorized directories.
date: "2026-09-22T19:53:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:roomi-fields:notebooklm-mcp:*:*:*:*:*:*:*:*
vendors:
  - roomi-fields
products:
  - notebooklm-mcp (>= 1.6.0, < 2.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vault_batch tool and the equivalent POST /batch-to-vault HTTP endpoint accepted a caller-supplied vault_dir path that was passed directly to path.resolve() + fs.mkdir() with no containment check.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: This allows an attacker to plant files in sensitive locations (autostart folders, shell startup files, etc.) for downstream exploitation.
    confidence_band: high
cves:
  - id: CVE-2026-61647
references:
  - https://github.com/advisories/GHSA-jjhp-8crj-mppq
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-61647
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade notebooklm-mcp to 2.0.3
      owner: IT Operations
      due: 48h
      evidence: Fixed in v2.0.3
    - action: Implement NOTEBOOKLM_VAULT_ROOT environment variable containment
      owner: IT Operations
      due: 48h
      evidence: Opt-in containment via NOTEBOOKLM_VAULT_ROOT env var.
  mitigation_plan:
    - priority: immediate
      action: Bind service to localhost and run as unprivileged user
      owner: IT Operations
      addresses: CVE-2026-61647
      evidence: Workarounds for users who cannot upgrade
---

A path traversal vulnerability exists in the @roomi-fields/notebooklm-mcp package, affecting versions 1.6.0 through 2.0.2. The vulnerability stems from improper sanitization of the `vault_dir` and `slug_prefix` parameters within the `vault.batch` MCP tool and the corresponding `/batch-to-vault` HTTP endpoint. The application directly utilizes these parameters in file system operations using `path.resolve()` and `fs.mkdir()` without enforcing boundary checks. An attacker or a compromised LLM driving the MCP interface can supply crafted path inputs containing directory traversal sequences (e.g., `..`) or absolute paths to write markdown and JSON files into sensitive directories on the host filesystem that the server process has permissions to access.

## Impact

Successful exploitation allows an attacker to write files anywhere the server process has write access. While the files are inert content (markdown/JSON), this vulnerability poses a significant risk in multi-user environments or when the MCP server is integrated with LLMs that ingest untrusted user content (e.g., via prompt injection). Attackers could potentially plant files in autostart folders or shell configuration files, leading to downstream command execution or system persistence.

## Recommendation

1. Upgrade @roomi-fields/notebooklm-mcp to version 2.0.3 or later immediately.
2. Following the upgrade, enforce directory containment by configuring the `NOTEBOOKLM_VAULT_ROOT` environment variable to a restricted directory path.
3. If immediate patching is not possible, restrict the exposure of the HTTP `/batch-to-vault` endpoint to local loopback interfaces only.
4. Ensure the service runs under a dedicated, unprivileged service account with write permissions restricted strictly to the intended vault location.
