---
brief_id: brief-2026-06-litespeed-cpanel-plugin-symlink
event_id: brief-2026-06-litespeed-cpanel-plugin-symlink
revision: 1
activity_at: "2026-06-15T19:07:14Z"
title: CVE-2026-54420 - LiteSpeed cPanel Plugin Symlink Following Vulnerability
slug: 2026-06-litespeed-cpanel-plugin-symlink
description: A critical UNIX symbolic link (Symlink) following vulnerability (CVE-2026-54420) in the LiteSpeed cPanel Plugin allows users with FTP or web shell access on shared CloudLinux/CageFS hosting environments to bypass security controls and potentially gain unauthorized access to sensitive system files.
date: "2026-06-15T19:07:14Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-06-15T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:litespeedtech:litespeed_cpanel_plugin:*:*:*:*:*:*:*:*
  - cpe:2.3:a:litespeedtech:litespeed_whm_plugin:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=EB7819E4-5D08-5B2B-B382-7EDE03F6667E&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - cpanel
  - litespeed
  - symlink
  - linux
  - web-hosting
vendors:
  - LiteSpeed
  - Litespeedtech
products:
  - cPanel Plugin
  - Litespeed_Cpanel_Plugin
affected_os:
  - CloudLinux
  - Linux
cves:
  - id: CVE-2026-54420
    cvss: 8.5
    epss: 0.00348
    kev: true
    kev_status: "true"
  - id: CVE-2025-46822
    epss: 0.03957
    kev_status: unknown
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-54420
  - https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54420
  - https://sploitus.com/exploit?id=EB7819E4-5D08-5B2B-B382-7EDE03F6667E&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=EB7819E4-5D08-5B2B-B382-7EDE03F6667E
  - type: url
    value: https://gist.githubusercontent.com/HORKimhab/24c89ee9a86a42aac88381334f8bfe48/raw
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-54420 Exploitation - Suspicious Symlink Creation to Sensitive Paths
    description: Detects creation of symbolic links from web-accessible directories to sensitive system files, which could indicate preparation for symlink following vulnerabilities like CVE-2026-54420. This activity is highly suspicious on shared hosting environments.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
      - T1552.001
    data_sources:
      - file_event
      - linux
  - title: Detects CVE-2026-54420 Exploitation - LiteSpeed Process Accessing Sensitive System Files
    description: Detects when a LiteSpeed web server process attempts to read highly sensitive system files. This could indicate a successful symlink following exploitation (CVE-2026-54420) or another form of arbitrary file read vulnerability.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1005
      - T1552.001
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-06-16T07:01:27Z"
    level: L2
    summary: poc_available; added CVE-2025-46822; OS linux
    sources:
      - sploitus
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-54420
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

CVE-2026-54420 describes a significant security flaw within the LiteSpeed cPanel Plugin, specifically a UNIX symbolic link (Symlink) following vulnerability. This vulnerability impacts shared hosting servers running CloudLinux with CageFS enabled, which is designed to isolate users. An attacker who has already obtained FTP credentials or established a web shell on such a server can leverage this flaw to bypass the intended security restrictions. By creating specially crafted symbolic links, they can trick the LiteSpeed cPanel Plugin into accessing or manipulating files outside of their allowed user directory, potentially leading to unauthorized information disclosure, privilege escalation, or modification of critical system files. This vulnerability poses a severe risk to multi-tenant hosting environments where user isolation is paramount.

## Attack Chain

1.  Attacker gains initial access to a shared hosting server through compromised FTP credentials or by exploiting another vulnerability (e.g., RFI, LFI) to upload and establish a web shell within a user's web accessible directory.
2.  Using the FTP access or web shell, the attacker uploads a malicious script (e.g., PHP, Perl, Python) capable of creating symbolic links on the file system.
3.  The attacker executes the malicious script, which creates a symbolic link (e.g., `/home/user/public_html/lscache_data/passwd_link`) pointing to a sensitive system file (e.g., `/etc/passwd`, `/etc/shadow`, database configuration files).
4.  The attacker then crafts and sends a specific HTTP request to the LiteSpeed cPanel Plugin's vulnerable endpoint, designed to trigger the plugin's file handling functionality.
5.  The LiteSpeed cPanel Plugin processes the request and, due to the symlink following vulnerability, resolves the attacker-controlled symlink and accesses the actual sensitive system file that the symlink points to, bypassing CageFS restrictions.
6.  The attacker leverages the plugin's access to read the content of the sensitive system file (e.g., `/etc/shadow`) or modify it, achieving unauthorized data exfiltration or system manipulation.
7.  The attacker uses the compromised data (e.g., hashed passwords) for further lateral movement, privilege escalation, or to maintain persistent access to the server environment.

## Impact

The successful exploitation of CVE-2026-54420 can lead to severe consequences, particularly in shared hosting environments. Attackers can gain unauthorized access to sensitive system files, including those containing user credentials (`/etc/shadow`), server configurations, or database secrets. This can result in widespread data breaches affecting multiple tenants on the same server, complete compromise of the hosting server, and potential disruption of services. For cloud services, the impact extends to the integrity and confidentiality of customer data hosted within the affected environments.

## Recommendation

*   Apply mitigations for CVE-2026-54420 in accordance with LiteSpeed's vendor instructions (refer to [https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/](https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/)) immediately.
*   Ensure compliance with CISA’s BOD 26-04 guidelines for prioritizing security updates (see [https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)).
*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious symlink creation and unauthorized access attempts by web server processes.
*   Enable comprehensive `file_event` and `process_creation` logging on your Linux servers, especially those running cPanel and LiteSpeed, to ensure telemetry for the provided Sigma rules.
*   If mitigations are unavailable, discontinue the use of the affected LiteSpeed cPanel Plugin as per CISA guidance for CVE-2026-54420.
