---
title: OpenClaw Sandbox Escape via Symlink Traversal
slug: 2026-04-openclaw-symlink
description: The openclaw npm package versions up to 2026.3.28 are vulnerable to a sandbox escape due to unrestricted file synchronization and symlink traversal, allowing attackers to potentially access or modify files outside the intended sandbox.
date: "2026-04-03T02:49:14Z"
severities:
  - high
tags:
  - npm
  - sandbox-escape
  - symlink
references:
  - https://github.com/advisories/GHSA-cwf8-44x6-32c2
rules:
  - title: Detect Symbolic Link Creation in OpenClaw Directories
    description: Detects the creation of symbolic links within directories typically used by OpenClaw, which could indicate an attempt to exploit the symlink traversal vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1547.009
    data_sources:
      - file_event
      - linux
  - title: Detect Access to Sensitive Files via OpenClaw Process
    description: Detects OpenClaw processes accessing sensitive files outside of its normal operating scope, potentially indicating exploitation of the symlink traversal vulnerability.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The openclaw npm package, a tool used for file synchronization and mirroring, contained a critical vulnerability affecting versions up to 2026.3.28. This flaw allowed for a sandbox escape through unrestricted file synchronization combined with symlink traversal. Specifically, the "mirror-boundary" could be bypassed, enabling malicious actors to read or write files outside the designated confines of the sandbox. The vulnerability was reported by AntAISecurityLab and addressed in version…
