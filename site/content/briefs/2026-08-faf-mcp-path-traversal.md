---
title: Arbitrary Local File Read and Write in faf-mcp
slug: 2026-08-faf-mcp-path-traversal
description: The faf-mcp package contains an arbitrary local file read/write vulnerability due to failure to validate user-supplied path arguments, allowing attackers to access or modify sensitive files outside the project directory.
date: "2026-08-19T22:34:43Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - faf-mcp (<= 2.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An MCP client — or an LLM prompt-injected via attacker-controlled content ... into issuing a tool call — can read any file the server process can read
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The server process can be made to read — and, via the file tools, write — files outside the intended .faf project context.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-j4r7-8ph4-43g3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade faf-mcp to 2.1.3
      owner: IT Operations
      due: 24h
      evidence: Fixed in 2.1.3 by confining every caller-supplied path before any filesystem access
  mitigation_plan:
    - priority: immediate
      action: Set FAF_ALLOWED_ROOTS to a restricted, non-sensitive directory
      owner: IT Operations
      addresses: Arbitrary local file read/write
      evidence: set FAF_ALLOWED_ROOTS (patched versions) to a single project directory for a hard directory boundary
---

The faf-mcp package (versions 2.1.2 and earlier) contains a critical path traversal vulnerability caused by the insecure handling of the `path` argument in its MCP (Model Context Protocol) tools. The application resolves caller-provided paths using `~` expansion and `path.resolve()` without confining them to a trusted project directory. This flaw allows an attacker to bypass intended directory restrictions using absolute paths or directory traversal sequences (../). By sending crafted tool calls via an MCP client, an attacker can read sensitive files, such as SSH keys, AWS credentials, or system configuration files, and overwrite files on the host system where the faf-mcp server process has sufficient permissions. This vulnerability was identified during a security audit and is remediated in version 2.1.3 through robust path canonicalization and directory confinement.

## Impact

Successful exploitation allows an attacker to perform unauthorized file system operations, leading to potential credential theft, information disclosure, and system compromise. Attackers can reach critical files such as `~/.ssh/id_rsa`, `~/.aws/credentials`, and `/etc/passwd`. Because the server operates over stdio and responds to tool calls, this vulnerability is highly susceptible to exploitation through LLM prompt injection, where an agent processing malicious external content is coerced into executing these unauthorized file operations.

## Recommendation

* Upgrade to faf-mcp version 2.1.3 or later immediately to apply the path confinement logic in `safe-path.ts`.
* If upgrading is not immediately feasible, restrict the use of the server to trusted environments and define the `FAF_ALLOWED_ROOTS` environment variable to explicitly bound access to a single, low-risk project directory.
* Implement endpoint monitoring to detect unauthorized file access patterns from the faf-mcp process (or the parent node process) targeting sensitive configuration paths outside the expected working directory.
