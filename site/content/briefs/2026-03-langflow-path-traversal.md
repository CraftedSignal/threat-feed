---
title: Langflow Path Traversal Vulnerability (CVE-2026-33497)
slug: 2026-03-langflow-path-traversal
description: A path traversal vulnerability in Langflow versions before 1.7.1 allows unauthenticated attackers to read sensitive files via the download_profile_picture endpoint due to insufficient filtering of the folder_name and file_name parameters.
date: "2026-03-25T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33497
  - https://github.com/langflow-ai/langflow/security/advisories/GHSA-ph9w-r52h-28p7
rules:
  - title: Detect Langflow Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-33497) in Langflow by monitoring for path traversal sequences in requests to the /profile_pictures endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive Files via Path Traversal
    description: Detects access attempts to common sensitive files (e.g., /etc/passwd) via path traversal in web server logs. Can be used to detect successful exploitation of CVE-2026-33497 in Langflow and other path traversal vulnerabilities.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Langflow, a tool designed for building and deploying AI-powered agents and workflows, is vulnerable to a path traversal attack (CVE-2026-33497) in versions prior to 1.7.1. The vulnerability resides within the download_profile_picture function of the `/profile_pictures/{folder_name}/{file_name}` endpoint. Due to inadequate filtering of the `folder_name` and `file_name` parameters, an attacker can manipulate these inputs to traverse directories and potentially access sensitive files, including…
