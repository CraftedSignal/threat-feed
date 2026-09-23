---
title: Multiple Vulnerabilities in HPE Aruba Analytics and Location Engine
slug: 2026-09-hpe-aruba-vulns
description: Multiple high-severity vulnerabilities in HPE Aruba Analytics and Location Engine (ALE) allow for remote code execution, privilege escalation, and denial-of-service.
date: "2026-09-23T13:55:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-76708
    cvss: 9.8
  - id: CVE-2026-76717
    cvss: 5.3
---

HPE Aruba Networking has released security bulletin HPESBNW05137 addressing multiple vulnerabilities identified in the Analytics and Location Engine (ALE) software. These vulnerabilities, tracked under CVE-2026-76708 through CVE-2026-76717, affect all versions prior to 5.1.0.0. An unauthenticated attacker could potentially exploit these flaws to achieve remote code execution (RCE), escalate privileges to gain full administrative control, or trigger a remote denial-of-service (DoS) condition on affected infrastructure. Given the critical
