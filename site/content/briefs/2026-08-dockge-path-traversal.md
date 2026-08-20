---
title: Path Traversal Vulnerability in Dockge (CVE-2026-73040)
slug: 2026-08-dockge-path-traversal
description: Dockge fails to validate stack names in read and delete operations, allowing authenticated or unauthenticated attackers to perform arbitrary file reads or recursive directory deletion via path traversal.
date: "2026-08-20T21:19:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-73040
  - path-traversal
  - rce
  - web-vulnerability
vendors:
  - Dockge
products:
  - Dockge
cves:
  - id: CVE-2026-73040
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73040
---

Dockge, a management tool for Docker Compose stacks, contains a path traversal vulnerability identified as CVE-2026-73040. The vulnerability exists because the application validates stack names only during the 'save' operation. The 'validate()' function in 'backend/stack.ts' enforces an allow-list regex (^[a-z0-9_-]+$), but this check is bypassed by other functions like 'Stack.getStack', which directly constructs paths using user-provided names without sanitization.

Attackers can pass traversal sequences (e.g., '../') via socket handlers to target files and directories outside the intended 'stacksDir'. An authenticated user, or any user on an instance configured with 'disableAuth', can read sensitive files like '.env' or compose YAML files, or trigger recursive deletion of directories if the target contains a valid Compose file. Given that Dockge often runs with root privileges and active Docker socket access, this vulnerability allows for broad system-level impact, including the deletion of unrelated host directories or the theft of credentials stored in environment files.

## Impact

Successful exploitation results in unauthorized disclosure of sensitive secrets (e.g., database passwords, API keys) from '.env' files or arbitrary file deletion on the underlying host filesystem. The impact is critical due to the typical execution of Dockge as the root user with unrestricted access to the Docker socket. The vulnerability affects instances where authentication is enabled (requiring valid credentials) and is trivially exploitable on instances configured with 'disableAuth'.

## Recommendation

1. Upgrade to the patched version of Dockge immediately upon release to address the validation gap in 'backend/stack.ts'.
2. Disable the 'disableAuth' configuration option in all production environments to require mandatory authentication.
3. Monitor web server and Docker socket proxy logs for requests containing traversal patterns such as '../' or encoded directory sequences.
4. Restrict access to the Docker socket to ensure that even if the application is compromised, the impact on the broader host filesystem is minimized.
