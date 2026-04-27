---
title: SiYuan Note Taking Application Directory Traversal Vulnerability
slug: 2026-03-siyuan-traversal
description: SiYuan note taking application is vulnerable to a directory traversal via the /api/file/readDir endpoint, which does not require authentication, allowing an attacker to enumerate the directory structure and retrieve file names, potentially leading to arbitrary document reading.
date: "2026-03-26T12:00:00Z"
severities:
  - critical
tags:
  - directory-traversal
  - siyuan
  - cve-2026-33670
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://github.com/advisories/GHSA-xmw9-6r43-x9ww
rules:
  - title: SiYuan Directory Traversal Attempt
    description: Detects attempts to exploit the directory traversal vulnerability in SiYuan via the /api/file/readDir endpoint.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
  - title: SiYuan Directory Traversal - Suspicious Path in Request
    description: Detects potential directory traversal attempts in SiYuan by looking for '..' sequences in the path parameter of /api/file/readDir requests.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The SiYuan note-taking application is susceptible to a critical directory traversal vulnerability affecting versions up to 0.0.0-20260317012524-fe4523fff2c8. The vulnerability resides in the `/api/file/readDir` endpoint, which lacks authentication. This allows unauthenticated attackers to send POST requests to enumerate directories and retrieve file names within the application's data and configuration directories. Successful exploitation allows a malicious actor to gain sensitive information…
