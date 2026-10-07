---
title: Multiple Vulnerabilities in SonicWall Secure Mobile Access
slug: 2026-10-sonicwall-sma-vulnerabilities
description: Multiple vulnerabilities, including RCE, SSRF, and XSS, affect SonicWall SMA 1000 series appliances, posing significant risks if chained to bypass authentication.
date: "2026-10-07T16:45:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cves:
  - id: CVE-2026-102255
    cvss: 10
  - id: CVE-2026-102256
    cvss: 7.8
  - id: CVE-2026-102257
    cvss: 7.2
  - id: CVE-2026-102258
    cvss: 6.1
---

The French National Cybersecurity Agency (ANSSI/CERT-FR) has issued an advisory regarding multiple critical vulnerabilities discovered in SonicWall Secure Mobile Access (SMA) 1000 series appliances. The flaws include Remote Code Execution (RCE), Server-Side Request Forgery (SSRF), and Cross-Site Scripting (XSS). These vulnerabilities are tracked under CVE-2026-102255, CVE-2026-102256, CVE-2026-102257, and CVE-2026-102258.

While the vendor has not reported active exploitation for these specific identifiers as of October 7, 2026, the CERT-FR highlights a recurring pattern of exploitation on these platforms. Attackers have previously chained SSRF vulnerabilities to bypass authentication mechanisms, subsequently leveraging RCE vulnerabilities to gain unauthorized control of the appliances
