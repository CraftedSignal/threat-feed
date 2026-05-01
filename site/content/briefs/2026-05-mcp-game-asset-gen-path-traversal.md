---
title: Flux159 mcp-game-asset-gen Path Traversal Vulnerability
slug: 2026-05-mcp-game-asset-gen-path-traversal
description: A path traversal vulnerability exists in Flux159 mcp-game-asset-gen version 0.1.0, where manipulation of the `statusFile` argument in the `image_to_3d_async` function allows for remote exploitation.
date: "2026-05-01T21:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - web-application
vendors:
  - Flux159
products:
  - mcp-game-asset-gen 0.1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7594
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7594
  - https://github.com/Flux159/mcp-game-asset-gen/
  - https://github.com/Flux159/mcp-game-asset-gen/issues/3
  - https://vuldb.com/submit/805508
  - https://vuldb.com/vuln/360547
  - https://vuldb.com/vuln/360547/cti
rules:
  - title: Detect Path Traversal Attempt via statusFile Parameter
    description: Detects attempts to exploit CVE-2026-7594 by identifying path traversal sequences in the statusFile parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Process Creation Related to CVE-2026-7594 Exploitation
    description: Detects potential exploitation of CVE-2026-7594 by monitoring for suspicious process creation events following path traversal attempts.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7594, has been discovered in Flux159 mcp-game-asset-gen version 0.1.0. The vulnerability resides within the `image_to_3d_async` function located in the `src/index.ts` file of the MCP Interface component. Successful exploitation allows a remote attacker to manipulate the `statusFile` argument, potentially leading to unauthorized file access and modification. Public exploits are available, increasing the risk of widespread exploitation. The project maintainers were notified via an issue report, but have not yet addressed the vulnerability. This lack of response, coupled with the existence of public exploits, elevates the urgency for defenders.

## Attack Chain

1.  The attacker identifies a vulnerable instance of mcp-game-asset-gen 0.1.0 running on a remote server.
2.  The attacker crafts a malicious HTTP request targeting the `image_to_3d_async` function.
3.  Within the request, the attacker manipulates the `statusFile` argument to include path traversal sequences (e.g., "../").
4.  The server-side application processes the request, using the attacker-controlled `statusFile` value to construct a file path.
5.  Due to insufficient input validation, the path traversal sequences are not properly sanitized.
6.  The application attempts to read or write to a file outside the intended directory, based on the manipulated path.
7.  If successful, the attacker gains unauthorized access to sensitive files or overwrites critical system files.
8.  The attacker leverages the file access to further compromise the system, potentially leading to code execution or data exfiltration.

## Impact

Successful exploitation of this path traversal vulnerability could allow attackers to read sensitive files, overwrite critical system files, or even achieve remote code execution on the affected server. This could lead to data breaches, system instability, or complete server compromise. Given the availability of public exploits, organizations using mcp-game-asset-gen 0.1.0 are at immediate risk.

## Recommendation

*   Apply input validation and sanitization to the `statusFile` argument within the `image_to_3d_async` function to prevent path traversal, addressing CVE-2026-7594.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., "../") in the `statusFile` parameter using the provided Sigma rule.
*   Implement the Sigma rule targeting process creation events related to the exploitation of CVE-2026-7594.
