---
title: SiYuan Note Reflected XSS Vulnerability in SVG Processing
slug: 2026-04-siyuan-xss
description: SiYuan Note versions prior to the fix for commit f09953afc57a are vulnerable to reflected cross-site scripting (XSS) via a namespace prefix bypass in the SanitizeSVG function when handling dynamic icons, allowing unauthenticated attackers to execute arbitrary JavaScript in a victim's browser.
date: "2026-04-01T00:30:01Z"
severities:
  - high
tags:
  - xss
  - siyuan
  - svg
  - reflected-xss
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-73g7-86qr-jrg3
rules:
  - title: Detect SiYuan SVG XSS Attempt
    description: Detects attempts to exploit the SiYuan SVG XSS vulnerability by identifying requests with namespace-prefixed script tags in the content parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SiYuan SVG XSS Attempt (iframe)
    description: Detects attempts to exploit the SiYuan SVG XSS vulnerability by identifying requests with namespace-prefixed iframe tags in the content parameter.
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

SiYuan Note, a note-taking application, is susceptible to a reflected XSS vulnerability in its dynamic icon generation functionality. This flaw, present in versions prior to commit f09953afc57a, arises from an insufficient sanitization of SVG content, specifically failing to account for namespace prefixes in SVG elements. The vulnerability resides in the `/api/icon/getDynamicIcon` endpoint, which is accessible without authentication.  An attacker can exploit this by crafting a malicious SVG…
