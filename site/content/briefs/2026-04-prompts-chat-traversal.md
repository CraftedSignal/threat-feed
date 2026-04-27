---
title: prompts.chat Path Traversal Vulnerability (CVE-2026-22661)
slug: 2026-04-prompts-chat-traversal
description: A path traversal vulnerability exists in prompts.chat prior to commit 0f8d4c3, allowing attackers to write arbitrary files to the client system by crafting malicious ZIP archives with unsanitized filenames.
date: "2026-04-04T12:00:00Z"
severities:
  - high
tags:
  - path-traversal
  - file-write
  - code-execution
  - cve-2026-22661
  - prompts.chat
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-22661
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22661
rules:
  - title: Detect Path Traversal in Filenames via Web Logs
    description: Detects attempts to exploit path traversal vulnerabilities by identifying '..' sequences in filenames within HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal in POST requests via Web Logs
    description: 'Detects attempts to exploit path traversal vulnerabilities by identifying ''..'' sequences in filenames within HTTP POST requests. '
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

prompts.chat, a software application, is vulnerable to a path traversal attack (CVE-2026-22661) in versions prior to commit 0f8d4c3. This vulnerability stems from insufficient server-side validation of filenames within skill file archives. A remote attacker can exploit this by crafting malicious ZIP archives that contain filenames with path traversal sequences (e.g., ../). When a vulnerable prompts.chat instance extracts these archives, the lack of proper sanitization allows the attacker to…
