---
title: Incomplete Path Traversal Fix in mcp-atlassian Allows RCE
slug: 2026-09-mcp-atlassian-traversal
description: An incomplete path traversal fix in the mcp-atlassian Python package allows attackers to overwrite application source modules and achieve remote code execution via a Confluence attachment upload.
date: "2026-09-23T01:57:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-77271
---

The `mcp-atlassian` package (versions 0.17.0 through 0.21.0) contains an incomplete path traversal fix for CVE-2026-77271. The utility function `validate_safe_path()` is intended to prevent unauthorized file writes; however, it defaults to `os.getcwd()` when a `base_dir` is not explicitly provided. In typical containerized deployments, the working directory is the application root (e.g., `/app`), meaning the validation logic inadvertently allows file operations within the source code directory. An attacker with existing write access to a Confluence instance can leverage the `confluence_download_attachment` MCP tool to overwrite critical Python source modules. Subsequent process restarts or module reloads execute the injected malicious code, leading to full remote code execution.

## Attack Chain

1. Att
