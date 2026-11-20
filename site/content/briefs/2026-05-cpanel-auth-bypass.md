---
brief_id: brief-2026-05-02-cpanel-auth-bypass
event_id: brief-2026-05-02-cpanel-auth-bypass
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:6718398ea786f3d65ca6b5687056bffefed10af7c15b6bb4e7ca517cf0bd9ff5
    summary: exploited:true; KEV CVE-2026-41940
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Critical Authentication Bypass Vulnerability in cPanel & WHM (CVE-2026-41940)
slug: 2026-05-cpanel-auth-bypass
description: CVE-2026-41940 is a critical authentication bypass vulnerability in cPanel & WHM, allowing unauthenticated remote attackers to gain administrative access by manipulating session data.
date: "2026-04-30T12:16:14Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-04-30T00:00:00Z"
  confidence: high
tags:
  - authentication bypass
  - cPanel
  - web hosting
  - vulnerability
vendors:
  - cPanel
products:
  - cPanel & WHM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41940
    cvss: 9.8
    kev: true
    kev_status: "true"
references:
  - https://ccb.belgium.be/advisories/warning-critical-authentication-bypass-cpanel-whm-patch-immediately
  - https://support.cpanel.net/hc/en-us/articles/40073787579671-Security-CVE-2026-41940-cPanel-WHM-WP2-Security-Update-04-28-2026
  - https://www.rapid7.com/blog/post/etr-cve-2026-41940-cpanel-whm-authentication-bypass/
  - https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940/
rules:
  - title: Detect Suspicious cPanel Login Attempts via POST Request
    description: Detects suspicious POST requests to the cPanel login page, potentially indicating exploitation of CVE-2026-41940.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect cPanel Account Creation from Unfamiliar IPs
    description: Detects cPanel account creation events originating from previously unseen IP addresses.  This may indicate unauthorized access after CVE-2026-41940 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-41940
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

A critical authentication bypass vulnerability, CVE-2026-41940, affects all versions of cPanel & WHM. This vulnerability allows unauthenticated remote attackers to gain administrative access to affected systems due to improper handling of session data. Public technical analyses and proof-of-concept code are available, significantly lowering the barrier to exploitation. There are indications that the vulnerability has been actively exploited in the wild, potentially as a zero-day. cPanel & WHM is commonly exposed to the internet and manages hosting environments, making it an attractive target for attackers seeking control over hosting infrastructures and numerous websites.

## Attack Chain

1.  An unauthenticated attacker identifies a cPanel & WHM server exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the cPanel & WHM login endpoint.
3.  The crafted request manipulates session creation and processing by injecting controlled data into the session files.
4.  This injected data alters authentication-related attributes within the session, bypassing the normal authentication flow.
5.  The attacker successfully establishes a session that is treated as fully authenticated without providing valid credentials.
6.  With administrative privileges, the attacker gains full control over the cPanel server.
7.  The attacker accesses hosted websites and databases, potentially compromising sensitive data.
8.  The attacker establishes persistence through backdoors or additional user accounts, ensuring continued access to the compromised system.

## Impact

Successful exploitation of CVE-2026-41940 allows attackers to gain complete control over cPanel & WHM servers. This can lead to the compromise of hosted websites, databases, and sensitive customer data. Given the central role of cPanel in hosting environments, this vulnerability can result in large-scale compromise affecting multiple customers and services. The widespread use of cPanel & WHM makes this a high-impact vulnerability.

## Recommendation

*   Apply the security patch provided by cPanel to address CVE-2026-41940 immediately after thorough testing to prevent exploitation.
*   Implement increased monitoring and detection capabilities to identify suspicious activity related to CVE-2026-41940 as recommended by CCB.
*   Review web server logs for unusual patterns or requests targeting cPanel login endpoints to detect potential exploitation attempts. Create a Sigma rule based on webserver logs.
*   Monitor for unauthorized changes to user accounts or the creation of new administrative accounts on cPanel servers. Create a Sigma rule based on process creation logs.
