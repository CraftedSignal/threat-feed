---
title: Adobe Connect XSS Vulnerability Leading to Privilege Escalation
slug: 2026-04-adobe-connect-xss
description: Adobe Connect versions 2025.3, 12.10, and earlier are susceptible to a Cross-Site Scripting (XSS) vulnerability (CVE-2026-34617) that can lead to privilege escalation if a user interacts with a malicious URL or compromised web page.
date: "2026-04-14T18:17:36Z"
severities:
  - high
tags:
  - adobe-connect
  - xss
  - cve-2026-34617
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-34617
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34617
rules:
  - title: Detect Potential XSS in Adobe Connect URI
    description: Detects potential XSS attacks targeting Adobe Connect by looking for common XSS payloads in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Potential XSS in Adobe Connect Request Body
    description: Detects potential XSS attacks targeting Adobe Connect by looking for common XSS payloads in the HTTP request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Adobe Connect versions 2025.3, 12.10, and prior are vulnerable to a Cross-Site Scripting (XSS) attack, identified as CVE-2026-34617. This vulnerability allows a low-privileged attacker to inject malicious scripts into a web page viewed by other users. Successful exploitation requires user interaction, such as clicking a crafted URL or interacting with a compromised page within the Adobe Connect environment. The vulnerability could allow an attacker to gain elevated access or control over a…
