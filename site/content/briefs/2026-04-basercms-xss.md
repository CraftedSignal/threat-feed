---
title: baserCMS DOM-Based Cross-Site Scripting Vulnerability (CVE-2026-32734)
slug: 2026-04-basercms-xss
description: baserCMS versions prior to 5.2.3 are vulnerable to DOM-based Cross-Site Scripting (XSS) due to improper neutralization of input during web page generation, potentially allowing a remote attacker to execute arbitrary JavaScript in a user's browser.
date: "2026-03-31T01:18:26Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - xss
  - vulnerability
  - basercms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32734
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32734
  - https://basercms.net/security/JVN_20837860
  - https://github.com/baserproject/basercms/releases/tag/5.2.3
  - https://github.com/baserproject/basercms/security/advisories/GHSA-677c-xv24-crgx
rules:
  - title: Detect baserCMS CVE-2026-32734 Exploit Attempt
    description: Detects potential exploit attempts targeting the baserCMS DOM-based XSS vulnerability (CVE-2026-32734).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect baserCMS CVE-2026-32734 Exploit Attempt (Encoded)
    description: Detects potential exploit attempts targeting the baserCMS DOM-based XSS vulnerability (CVE-2026-32734) using URL encoded payloads.
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

baserCMS, a website development framework, is susceptible to DOM-based cross-site scripting (XSS) attacks in versions prior to 5.2.3. This vulnerability, identified as CVE-2026-32734, arises from the improper neutralization of input during the creation of tags. An attacker can exploit this by injecting malicious JavaScript code into the DOM, which is then executed in the victim's browser when they interact with the crafted web page. Successful exploitation can lead to session hijacking…
