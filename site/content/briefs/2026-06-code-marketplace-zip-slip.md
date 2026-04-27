---
title: Coder Code-Marketplace Zip Slip Vulnerability
slug: 2026-06-code-marketplace-zip-slip
description: A Zip Slip vulnerability in coder/code-marketplace allows authenticated users to upload malicious VSIX files containing path traversal entries, leading to arbitrary file writes outside the extension directory and potentially enabling persistence.
date: "2026-04-04T06:29:50Z"
severities:
  - high
tags:
  - zip-slip
  - path-traversal
  - code-marketplace
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-8x9r-hvwg-c55h
  - https://coder.com/security/policy
  - https://github.com/coder/code-marketplace/releases/tag/v2.4.2
rules:
  - title: Detect Suspicious File Creation in Sensitive Directories
    description: Detects the creation of new files in sensitive directories, potentially indicating exploitation of path traversal vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - linux
  - title: Detect VSIX Uploads with Path Traversal
    description: Detects VSIX uploads with potential path traversal attempts based on request parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A Zip Slip vulnerability (CVE-2026-35454) exists in the Coder code-marketplace application, specifically in versions up to 2.4.1. The vulnerability stems from improper sanitization of zip entry names during VSIX file extraction, which allows an attacker to write files to arbitrary locations on the server. This flaw, discovered by Kandlaguduru Vamsi and detailed in GHSA-8x9r-hvwg-c55h, can be exploited by any authenticated user with upload privileges. Successful exploitation could lead to…
