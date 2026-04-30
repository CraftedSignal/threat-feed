---
title: OpenClaw Path Traversal Vulnerability (CVE-2026-35668)
slug: 2026-04-openclaw-path-traversal
description: OpenClaw before 2026.3.24 is vulnerable to path traversal, allowing sandboxed agents to read arbitrary files from other agents' workspaces via manipulated URL parameters.
date: "2026-04-10T17:17:09Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - vulnerability
  - openclaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35668
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35668
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-hr5v-j9h9-xjhg
  - https://www.vulncheck.com/advisories/openclaw-sandbox-media-root-bypass-via-unnormalized-mediaurl-and-fileurl-parameters
rules:
  - title: Detect OpenClaw Path Traversal Attempt via URL Parameters
    description: Detects potential path traversal attempts in OpenClaw via suspicious `mediaUrl` or `fileUrl` parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Path Traversal Attempt via Web Logs
    description: Detects path traversal attempts targeting OpenClaw by identifying '..' sequences in URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.24 are susceptible to a path traversal vulnerability (CVE-2026-35668) that compromises sandbox enforcement. This flaw allows a sandboxed agent to read arbitrary files from another agent's workspace by exploiting weaknesses in the handling of `mediaUrl` and `fileUrl` parameters. The vulnerability stems from incomplete parameter validation within the `normalizeSandboxMediaParams` function and the absence of `mediaLocalRoots` context, which enables attackers to bypass intended sandbox restrictions and access sensitive data, such as API keys and configuration files, located outside the agent's designated sandbox root. Successful exploitation allows unauthorized data access, potentially leading to lateral movement or data exfiltration.

## Attack Chain

1.  An attacker identifies an OpenClaw instance running a version prior to 2026.3.24.
2.  The attacker crafts a malicious request containing either a `mediaUrl` or `fileUrl` parameter.
3.  The crafted URL includes path traversal sequences (e.g., `../`) designed to navigate outside the intended sandbox directory.
4.  The `normalizeSandboxMediaParams` function processes the URL but fails to adequately sanitize or normalize the path, due to insufficient validation.
5.  The lack of proper `mediaLocalRoots` context during path resolution further contributes to the bypass.
6.  The application attempts to access the file specified by the manipulated URL.
7.  Due to the path traversal vulnerability, the application reads a file outside the intended sandbox root, potentially revealing sensitive information like API keys.
8.  The attacker retrieves the contents of the targeted file, completing the unauthorized access.

## Impact

Successful exploitation of CVE-2026-35668 can lead to the disclosure of sensitive information, including API keys and configuration data, stored within other agents' workspaces. This unauthorized access can enable attackers to perform lateral movement, escalate privileges, or exfiltrate valuable data. While specific victim counts are unavailable, any OpenClaw deployment running a vulnerable version is at risk. The impact is heightened in environments where OpenClaw agents handle sensitive data or manage critical infrastructure.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.24 or later to remediate CVE-2026-35668 and address the underlying path traversal vulnerability.
*   Implement input validation and sanitization for all URL parameters, especially those related to file or media access, to prevent path traversal attacks.
*   Apply the provided Sigma rule to detect suspicious requests containing path traversal sequences in `mediaUrl` or `fileUrl` parameters within web server logs.
*   Review and strengthen sandbox configurations to ensure proper isolation between OpenClaw agents and restrict access to sensitive files.
