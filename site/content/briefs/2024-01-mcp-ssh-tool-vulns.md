---
title: mcp-ssh-tool Path Traversal and Timing Attack Vulnerabilities
slug: 2024-01-mcp-ssh-tool-vulns
description: mcp-ssh-tool versions 2.1.0 and earlier have a policy bypass in transfer path handling and expose a timing side channel in bearer-token comparison for HTTP deployments, addressed in version 2.1.1.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - timing-attack
  - npm
vendors:
  - npm
products:
  - mcp-ssh-tool
references:
  - https://github.com/advisories/GHSA-j7h9-2jh7-g967
rules:
  - title: Detect mcp-ssh-tool Suspicious File Transfers via Command Line
    description: Detects suspicious file transfer commands indicative of path traversal attempts in mcp-ssh-tool by monitoring command-line arguments. This rule focuses on identifying commands with relative or absolute paths potentially bypassing intended restrictions.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - process_creation
      - linux
  - title: Detect mcp-ssh-tool HTTP Bearer Token Authentication Attempts
    description: Detects potential brute-force attempts against mcp-ssh-tool HTTP bearer token authentication by monitoring web server logs for numerous failed authentication attempts from the same source IP within a short timeframe. This could indicate an attacker trying to exploit the timing side channel.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
rules_count: 2
---

Versions 2.1.0 and earlier of `mcp-ssh-tool`, a tool often used in CI/CD environments, contain security vulnerabilities related to file transfer path authorization and HTTP bearer authentication. Specifically, the tool suffers from insufficient local path policy enforcement in transfer-related filesystem handling, leading to potential bypasses of configured path restrictions. Additionally, a non-constant-time HTTP bearer token comparison exposes a timing side channel. The vulnerability allows attackers with sufficient access to potentially read or write files outside of their intended scope. Upgrade to version 2.1.1 or implement provided workarounds to mitigate risks.

## Attack Chain

1. An attacker gains access to an MCP client, either through compromised credentials or a vulnerable service.
2. The attacker crafts a file transfer request with a manipulated path, exploiting insufficient canonicalization in the `mcp-ssh-tool`'s path policy checks.
3. The crafted path bypasses the configured deny-prefix path policy.
4. The attacker initiates a file transfer operation targeting a restricted file system location.
5. The `mcp-ssh-tool` incorrectly authorizes the transfer due to the policy bypass.
6. The attacker successfully reads or writes files outside of the intended scope.
7. In HTTP deployments, an attacker attempts to authenticate using a brute-force approach, leveraging timing differences in bearer token comparison.
8. By analyzing response times, the attacker identifies valid token characters and reconstructs the valid bearer token over time.

## Impact

Successful exploitation of the path traversal vulnerability could allow unauthorized access to sensitive files and directories on the server. The timing side channel vulnerability in bearer token comparison could lead to unauthorized access to the system via HTTP. The severity of the impact is dependent on the file system permissions and sensitivity of the data exposed.

## Recommendation

*   Upgrade to `mcp-ssh-tool >= 2.1.1` to remediate both the path traversal and timing attack vulnerabilities.
*   For deployments that cannot immediately upgrade, avoid exposing HTTP transport beyond loopback to mitigate the timing attack.
*   Implement strict filesystem policy configuration as described in the `mcp-ssh-tool` documentation to minimize the risk of path traversal.
*   Monitor audit logs for unexpected transfer operations to identify and respond to potential exploit attempts.
