---
title: XenForo Path Disclosure via Open-Basedir Restrictions (CVE-2025-71282)
slug: 2026-04-xenforo-path-disclosure
description: XenForo before 2.3.7 discloses filesystem paths through exception messages triggered by open_basedir restrictions, allowing attackers to gain sensitive information about the server's directory structure.
date: "2026-04-01T01:16:40Z"
severities:
  - medium
tags:
  - path-disclosure
  - cve-2025-71282
  - xenforo
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2025-71282
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71282
  - https://www.vulncheck.com/advisories/xenforo-path-disclosure-via-open-basedir-exceptions
  - https://xenforo.com/community/threads/xenforo-2-3-7-released-includes-security-fixes.232121/
rules:
  - title: Detect XenForo Path Disclosure Attempt via HTTP Error Codes
    description: Detects attempts to trigger XenForo path disclosure by monitoring for specific HTTP error codes (e.g., 500) accompanied by responses containing filesystem paths.
    platform: sigma
    severity: medium
    tactics:
      - information_gathering
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect XenForo Open Basedir Path Disclosure in Web Logs
    description: Detects attempts to trigger XenForo path disclosure by monitoring for server responses containing filesystem paths in error messages, indicative of open_basedir violations.
    platform: sigma
    severity: medium
    tactics:
      - information_gathering
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2025-71282 details a path disclosure vulnerability affecting XenForo versions prior to 2.3.7. The vulnerability arises due to insufficient restrictions on error message generation when encountering `open_basedir` restrictions. By triggering specific errors related to file access, an attacker can elicit exception messages that reveal the server's internal filesystem structure. This information can then be leveraged to further understand the system's configuration, identify potential attack…
