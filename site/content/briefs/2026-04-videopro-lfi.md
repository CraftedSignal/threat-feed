---
title: CactusThemes VideoPro Theme Local File Inclusion Vulnerability (CVE-2025-58913)
slug: 2026-04-videopro-lfi
description: CVE-2025-58913 is a PHP Local File Inclusion vulnerability in the CactusThemes VideoPro WordPress theme, affecting versions from n/a through 2.3.8.1 due to improper control of the filename for include/require statements, potentially allowing unauthorized file access.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
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

A local file inclusion (LFI) vulnerability has been identified in the CactusThemes VideoPro WordPress theme. Assigned CVE-2025-58913, this vulnerability exists due to the improper handling of filenames passed to include or require statements within the PHP code of the theme. Specifically, versions of VideoPro from its initial release up to and including version 2.3.8.1 are affected. Successful exploitation of this vulnerability could allow an attacker to read sensitive files on the server, potentially leading to further compromise. The vulnerability was reported by Patchstack. Defenders should prioritize patching or removing the vulnerable theme.

## Attack Chain

1. The attacker identifies a VideoPro installation running a vulnerable version (<= 2.3.8.1).
2. The attacker crafts a malicious HTTP request targeting a PHP script within the VideoPro theme that uses `include` or `require` statements.
3. The attacker injects a path traversal sequence (e.g., `../../../../etc/passwd`) into the filename parameter of the HTTP request.
4. The vulnerable PHP script, without proper sanitization of the filename, attempts to include the attacker-specified file.
5. If successful, the contents of the file (e.g., `/etc/passwd`) are exposed within the web server's response.
6. The attacker analyzes the exposed file contents for sensitive information such as user credentials or configuration details.
7. The attacker uses the obtained information to further compromise the server or other related systems.

## Impact

Successful exploitation of CVE-2025-58913 allows an attacker to read arbitrary files on the webserver hosting the vulnerable WordPress instance. This can lead to the exposure of sensitive data such as configuration files containing database credentials, WordPress salts, or even source code. If sensitive credentials are leaked, an attacker could pivot to other systems or gain administrative access to the WordPress site. The vulnerable VideoPro theme is used by an unknown number of WordPress websites, representing a significant attack surface.

## Recommendation

*   Upgrade the CactusThemes VideoPro theme to a patched version (later than 2.3.8.1) or remove the theme entirely from WordPress installations to remediate CVE-2025-58913.
*   Deploy the Sigma rule "Detect VideoPro LFI Attempts via Path Traversal" to identify exploitation attempts against vulnerable VideoPro installations using path traversal sequences in URI queries.
*   Monitor web server logs (category `webserver`, product `linux`) for suspicious requests containing path traversal sequences (e.g., `../`, `../../`) in the URI query string, which may indicate LFI attempts.
