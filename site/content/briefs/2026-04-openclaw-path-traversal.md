---
title: OpenClaw Path Traversal Vulnerability (CVE-2026-35668)
slug: 2026-04-openclaw-path-traversal
description: OpenClaw before 2026.3.24 is vulnerable to path traversal, allowing sandboxed agents to read arbitrary files from other agents' workspaces via manipulated URL parameters.
date: "2026-04-10T17:17:09Z"
severities:
  - high
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

OpenClaw versions prior to 2026.3.24 are susceptible to a path traversal vulnerability (CVE-2026-35668) that compromises sandbox enforcement. This flaw allows a sandboxed agent to read arbitrary files from another agent's workspace by exploiting weaknesses in the handling of `mediaUrl` and `fileUrl` parameters. The vulnerability stems from incomplete parameter validation within the `normalizeSandboxMediaParams` function and the absence of `mediaLocalRoots` context, which enables attackers to…
