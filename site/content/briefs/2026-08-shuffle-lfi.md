---
title: Local File Inclusion Vulnerability in Shuffle WordPress Theme
slug: 2026-08-shuffle-lfi
description: The Shuffle WordPress theme (<= 1.8) contains a Local File Inclusion vulnerability (CVE-2026-78566) that allows unauthenticated remote attackers to execute arbitrary PHP code on the host server.
date: "2026-08-25T10:08:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - wordpress
  - cve-2026-78566
vendors:
  - Edge-Themes
products:
  - Shuffle
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Shuffle theme for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.8.
    confidence_band: high
cves:
  - id: CVE-2026-78566
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78566
  - https://patchstack.com/database/wordpress/theme/shuffle/vulnerability/wordpress-shuffle-theme-1-8-local-file-inclusion-vulnerability
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/e154cb8e-db3c-4d08-a3ad-c72e7733cfce?source=cve
rules:
  - title: Detects CVE-2026-78566 Exploitation - LFI via Directory Traversal
    description: Detects potential LFI exploitation attempts against WordPress themes by monitoring for directory traversal patterns in URI requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory WordPress sites for Shuffle theme version <= 1.8
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects all versions up to 1.8.
  mitigation_plan:
    - priority: immediate
      action: Update Shuffle theme to the latest version
      owner: IT Operations
      addresses: CVE-2026-78566
      evidence: Vendor release of patched version.
---

The Shuffle theme for WordPress, developed by Edge-Themes, is susceptible to a Local File Inclusion (LFI) vulnerability identified as CVE-2026-78566. The vulnerability affects all versions up to and including 1.8. An unauthenticated attacker can exploit this flaw to include and execute arbitrary files stored on the underlying web server. This vulnerability, categorized as CWE-98, poses a significant risk to affected installations, as successful exploitation enables the execution of arbitrary PHP code, potentially leading to a full system compromise. The impact includes the ability to bypass access controls, exfiltrate sensitive application data, or achieve Remote Code Execution (RCE) if the environment allows for the uploading of files (such as images) that can then be processed via the LFI vector.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary PHP code on the server hosting the WordPress instance. This can lead to unauthorized access to the WordPress database, configuration files, and credentials stored in the application environment. If the server is not properly hardened, this vulnerability may lead to full web shell deployment and persistent access by an adversary.

## Recommendation

- Identify all WordPress installations within the environment utilizing the Shuffle theme by Edge-Themes.
- Update the Shuffle theme to the latest patched version immediately.
- If an update is unavailable, audit web server logs for suspicious requests containing directory traversal sequences (e.g., ../) in common URL parameters associated with theme file inclusion.
- Restrict the ability of the web server user to read files outside of the defined document root.
- Deploy the provided Sigma rule to detect attempts to exploit LFI vulnerabilities in web applications.
