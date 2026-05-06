---
title: ENOVIA Collaborative Industry Innovator Stored XSS Vulnerability (CVE-2025-10551)
slug: 2026-03-enovia-xss
description: A stored cross-site scripting (XSS) vulnerability in ENOVIA Collaborative Industry Innovator allows an attacker to execute arbitrary script code in a user's browser session by injecting malicious code into document management functions.
date: "2026-03-31T09:16:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - xss
  - cve-2025-10551
  - enovia
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-10551
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-10551
  - https://www.3ds.com/trust-center/security/security-advisories/cve-2025-10551
rules:
  - title: Detect Suspicious URI Containing HTML Script Tags
    description: Detects suspicious URI requests that contain HTML script tags, potentially indicating XSS attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious URI Containing Base64 Encoded Script Tags
    description: Detects suspicious URI requests that contain base64 encoded HTML script tags, potentially indicating XSS attacks.
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

CVE-2025-10551 is a stored XSS vulnerability affecting the Document Management feature within ENOVIA Collaborative Industry Innovator. This vulnerability exists in versions from Release 3DEXPERIENCE R2023x through Release 3DEXPERIENCE R2025x. A successful exploit allows an attacker to inject malicious JavaScript code into the application, which is then executed within the browser of any user who interacts with the compromised data.  This poses a significant risk to data confidentiality and…
