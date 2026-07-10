---
title: OpenClaw Sandbox Media Root Bypass via Unnormalized mediaUrl/fileUrl Parameter Keys
slug: 2024-05-openclaw-sandbox-bypass
description: A path traversal vulnerability in OpenClaw allows sandboxed agents to read arbitrary files from other agents' workspaces by exploiting unnormalized `mediaUrl` or `fileUrl` parameter keys, leading to potential exposure of sensitive data like API keys and session information.
date: "2024-05-01T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - sandbox-escape
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-hr5v-j9h9-xjhg
rules:
  - title: OpenClaw Suspicious Media URL Access
    description: Detects attempts to access files via mediaUrl or fileUrl parameters outside of the expected sandbox root.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: OpenClaw handlePluginAction mediaLocalRoots omission
    description: Detects execution of channel plugins without mediaLocalRoots context, indicating a potential sandbox bypass
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.24 contain a sandbox escape vulnerability that allows a sandboxed agent to bypass intended security restrictions and access files outside of its designated workspace. This is achieved by exploiting a path traversal vulnerability in the `normalizeSandboxMediaParams` function, which fails to properly sanitize the `mediaUrl` and `fileUrl` parameter keys. The `handlePluginAction` function further exacerbates this issue by omitting `mediaLocalRoots` from the dispatch context. This oversight allows malicious or compromised agents to read sensitive information, such as API keys, session data, and configuration files, from other agents' workspaces, effectively defeating the multi-agent sandbox isolation feature. The vulnerability can be triggered via prompt injection, multi-agent interaction, or malicious plugin instructions.

## Attack Chain

1. A sandboxed agent (Agent-A) initiates a message tool call with a crafted `mediaUrl` parameter pointing to a file in another agent's workspace (Agent-B), such as `mediaUrl: "~/.openclaw/workspace/agent-b/secret.txt"`.
2. The `normalizeSandboxMediaParams` function, responsible for sanitizing media parameters, skips the `mediaUrl` key because it's not included in the hardcoded allowlist of checked keys (`media`, `path`, `filePath`).
3. The `handlePluginAction` function dispatches an action to a channel plugin but omits the `mediaLocalRoots` context, preventing proper sandbox enforcement.
4. The plugin calls `loadWebMedia` without a restricted `mediaLocalRoots`, causing it to fall back to `getDefaultMediaLocalRoots()` which defaults to allowing access to the entire `~/.openclaw/` directory tree.
5. `loadWebMedia` reads the contents of the targeted file (`secret.txt`) from Agent-B's workspace.
6. The content of the secret file is then incorporated into the channel message.
7. The message, including the file content, is sent to the intended recipient.
8. The attacker successfully retrieves sensitive data from another agent's workspace, bypassing the intended sandbox isolation.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files from other agents' workspaces within the OpenClaw environment. This can lead to the compromise of sensitive information, including API keys, session data, configuration files with credentials, and conversation logs. The vulnerability affects OpenClaw versions up to and including 2026.3.14. If successful, the entire multi-agent sandbox isolation is defeated, undermining the security posture of the OpenClaw system.

## Recommendation

*   Apply the patch by upgrading to OpenClaw version 2026.3.24 or later to address the vulnerability in `normalizeSandboxMediaParams` and `handlePluginAction` (reference: Advisory Details).
*   Implement input validation and sanitization on all user-provided parameters, especially those related to file paths and URLs, to prevent path traversal attacks (reference: CWE-22).
*   Monitor process execution for attempts to access files outside of designated agent workspaces, using the Sigma rule provided below.
