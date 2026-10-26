---
brief_id: brief-2026-10-26-alertus-desktop-alert-rce
event_id: brief-2026-10-26-alertus-desktop-alert-rce
revision: 1
activity_at: "2026-10-26T22:07:01Z"
title: 'Alertus Desktop Alert: Unauthenticated Remote HTML Injection (CVE-2026-38903)'
slug: 2026-10-alertus-desktop-alert-rce
description: A public proof-of-concept (PoC) exists for CVE-2026-38903, an unauthenticated remote HTML injection vulnerability in Alertus Desktop Alert v5.4.98.0. The vulnerability stems from a certificate validation bypass that allows attackers to render arbitrary HTML and execute JavaScript within a Trident WebBrowser control.
date: "2026-10-26T22:07:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
tags:
  - HTML injection
  - certificate validation bypass
vendors:
  - Alertus
products:
  - Desktop Alert (v5.4.98.0)
affected_os:
  - Windows
cves:
  - id: CVE-2026-38903
    cvss: 6.1
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=8AB36901-52F0-5195-8367-1777996720AB
  - https://sploitus.com/exploit?id=8AB36901-52F0-5195-8367-1777996720AB&utm_source=rss&utm_medium=rss
---

Alertus Desktop Alert v5.4.98.0 for Windows is susceptible to remote HTML injection due to a failure in the PKI module to validate certificate chains. An attacker who can redirect DNS resolution can serve forged responses signed with an attacker-generated key. The client renders this input in a Trident (IE) WebBrowser control without sanitization, enabling JavaScript execution, protocol handler navigation, and the spawning of registered executables.
