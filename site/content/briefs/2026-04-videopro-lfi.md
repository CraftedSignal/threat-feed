---
title: CactusThemes VideoPro Theme Local File Inclusion Vulnerability (CVE-2025-58913)
slug: 2026-04-videopro-lfi
description: CVE-2025-58913 is a PHP Local File Inclusion vulnerability in the CactusThemes VideoPro WordPress theme, affecting versions from n/a through 2.3.8.1 due to improper control of the filename for include/require statements, potentially allowing unauthorized file access.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - wordpress
  - lfi
  - cve-2025-58913
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-58913
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-58913
  - https://patchstack.com/database/wordpress/theme/videopro/vulnerability/wordpress-videopro-theme-2-3-8-1-local-file-inclusion-vulnerability?_s_id=cve
rules:
  - title: Detect VideoPro LFI Attempts via Path Traversal
    description: Detects potential Local File Inclusion (LFI) attempts against CactusThemes VideoPro WordPress theme by identifying path traversal sequences in URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Detect VideoPro LFI Attempts via PHP Wrapper
    description: Detects potential Local File Inclusion (LFI) attempts against CactusThemes VideoPro WordPress theme by identifying php wrapper in URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A local file inclusion (LFI) vulnerability has been identified in the CactusThemes VideoPro WordPress theme. Assigned CVE-2025-58913, this vulnerability exists due to the improper handling of filenames passed to include or require statements within the PHP code of the theme. Specifically, versions of VideoPro from its initial release up to and including version 2.3.8.1 are affected. Successful exploitation of this vulnerability could allow an attacker to read sensitive files on the server…
