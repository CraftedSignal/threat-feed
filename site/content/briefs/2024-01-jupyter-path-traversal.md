---
title: Jupyter Server Path Traversal Vulnerability
slug: 2024-01-jupyter-path-traversal
description: Jupyter Server version 2.17.0 and earlier is vulnerable to a path traversal vulnerability due to an insufficient check on the root directory, allowing an authenticated user to access, read, write, and delete content outside the server's root directory in sibling directories that share the same prefix as the root directory, potentially leading to privilege escalation in multi-tenant environments.
date: "2026-05-05T16:49:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - privilege-escalation
  - jupyter
vendors:
  - Jupyter
products:
  - Jupyter Server (<= 2.17.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-5789-5fc7-67v3
  - https://gist.github.com/Yann-P/66d4982a965dee8fcb8dd89db29e7006
rules:
  - title: Detect Jupyter Server Path Traversal Attempt
    description: Detects attempts to exploit the Jupyter Server path traversal vulnerability by monitoring for suspicious API requests containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Jupyter Server Sibling Directory Access
    description: Detects access attempts to sibling directories by monitoring for specific API request patterns.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Jupyter Server, a widely used platform for interactive computing, has a path traversal vulnerability affecting versions 2.17.0 and earlier. This flaw stems from an inadequate `startswith()` check on the root directory, which fails to properly restrict access to sibling directories. An authenticated user can exploit this by crafting specific API requests to access content outside of the designated `root_dir`. This vulnerability is especially dangerous in multi-tenant server deployments using predictable naming schemes, such as `user1`, `user2`, etc., where one user could potentially access and modify files belonging to other users. The vulnerability was reported on May 5, 2026, and is identified as CVE-2026-35397. Defenders should prioritize patching and consider workarounds to prevent unauthorized access to sensitive data.

## Attack Chain

1.  An authenticated user logs into a vulnerable Jupyter Server instance.
2.  The attacker identifies the `root_dir` of their Jupyter environment.
3.  The attacker identifies a sibling directory that shares a prefix with the `root_dir` (e.g., if `root_dir` is `test`, a sibling directory might be `testtest`).
4.  The attacker crafts a POST request to the `/api/contents/` endpoint, using a path traversal sequence (`%2e%2e/`) followed by the sibling directory and the target file. For example: `/api/contents/%2e%2e/testtest/secret.txt/checkpoints`.
5.  The Jupyter Server's insufficient `startswith()` check allows the request to proceed without proper validation.
6.  The attacker gains unauthorized access to the target file within the sibling directory.
7.  The attacker can then read, write, or delete the accessed file, potentially escalating privileges or compromising sensitive data.
8.  The attacker leverages this access to compromise other user accounts or the Jupyter Server instance.

## Impact

Successful exploitation of this vulnerability allows an attacker to read, write, and delete files in directories sibling to the Jupyter Server's `root_dir`. This can lead to privilege escalation, especially in multi-tenant environments. For instance, in systems with predictable naming schemes like `user1`, `user2`, ..., `user10`, an attacker with access to `user1` could modify files belonging to `user10` - `user19`. The severity of this issue is heightened in scenarios where users can choose their folder names, as an attacker selecting a single-letter username could potentially compromise a significant number of sibling directories.

## Recommendation

*   Upgrade to Jupyter Server version 2.17.1 or later to patch CVE-2026-35397.
*   Implement stricter validation and sanitization of user inputs, specifically for file paths, to prevent path traversal attacks.
*   Deploy the Sigma rule "Detect Jupyter Server Path Traversal Attempt" to monitor for suspicious API requests containing path traversal sequences.
*   Review and revise folder naming schemes to avoid overlapping names in multi-tenant environments, as suggested in the advisory workaround.
