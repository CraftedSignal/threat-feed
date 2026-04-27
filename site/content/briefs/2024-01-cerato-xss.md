---
title: Zootemplate Cerato Theme Reflected XSS Vulnerability (CVE-2025-58920)
slug: 2024-01-cerato-xss
description: A reflected cross-site scripting (XSS) vulnerability exists in the Zootemplate Cerato WordPress theme (versions n/a through 2.2.18) due to improper neutralization of user-supplied input, potentially allowing attackers to execute arbitrary JavaScript in a user's browser.
date: "2026-04-10T14:16:25Z"
severities:
  - medium
tags:
  - xss
  - wordpress
  - reflected-xss
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-58920
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-58920
  - https://patchstack.com/database/wordpress/theme/cerato/vulnerability/wordpress-cerato-theme-2-2-18-reflected-cross-site-scripting-xss-vulnerability?_s_id=cve
ioc_counts:
  url: 1
rules:
  - title: Reflected XSS Attempt via GET
    description: Detects potential reflected XSS attacks by searching for common XSS payloads in GET request parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Reflected XSS Attempt via POST
    description: Detects potential reflected XSS attacks by searching for common XSS payloads in POST request parameters.
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

A reflected XSS vulnerability, identified as CVE-2025-58920, affects the Zootemplate Cerato WordPress theme. The vulnerability resides in versions ranging from n/a through 2.2.18. It stems from the improper neutralization of input during web page generation, which can allow an attacker to inject malicious scripts into a web page viewed by other users. Successful exploitation could allow an attacker to steal cookies, redirect users to malicious websites, or deface web pages. Given the widespread…
