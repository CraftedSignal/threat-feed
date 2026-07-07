---
title: CVE-2026-6101 — Arbitrary File Write in AMP for WP Plugin for WordPress
slug: 2026-07-amp-for-wp-file-write
description: An arbitrary file write vulnerability (CVE-2026-6101) exists in the AMP for WP – Accelerated Mobile Pages plugin for WordPress, affecting versions up to and including 1.1.12. This flaw, caused by unsafe ZIP file extraction and inadequate cleanup, allows authenticated attackers with Author-level access and administrator-granted permissions to write arbitrary files to web-accessible server locations, potentially leading to remote code execution.
date: "2026-07-07T14:18:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - arbitrary-file-write
  - rce
  - webserver
vendors:
  - AMP for WP
products:
  - AMP for WP – Accelerated Mobile Pages plugin < 1.1.13
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: makes it possible for authenticated attackers... to write arbitrary files to the server in a web-accessible location, potentially leading to remote code execution on hosts that execute PHP files in the uploads directory.
    confidence_band: high
cves:
  - id: CVE-2026-6101
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6101
---

The AMP for WP – Accelerated Mobile Pages plugin for WordPress, impacting versions up to and including 1.1.12, contains an arbitrary file write vulnerability, identified as CVE-2026-6101. This flaw stems from unsafe ZIP file extraction within the `ampforwp_save_local_font()` function, compounded by inadequate cleanup of nested directories and files. Exploitation requires authenticated attackers with Author-level access and administrator-granted permissions. Successful exploitation allows the attacker to write arbitrary files to web-accessible server locations, which can lead to remote code execution on the compromised WordPress instance. This vulnerability poses a significant risk to affected WordPress sites as it can lead to full system compromise.

## Attack Chain

1.  An attacker gains authenticated access to a WordPress site with Author-level privileges.
2.  An Administrator grants the attacker permissions that allow the use of a plugin feature which invokes the `ampforwp_save_local_font()` function.
3.  The attacker crafts a specially designed ZIP archive containing malicious PHP webshell code, structured to exploit path traversal during extraction.
4.  The attacker uploads this crafted ZIP file via the vulnerable WordPress plugin functionality, triggering the `ampforwp_save_local_font()` function.
5.  Due to unsafe ZIP file extraction, the malicious PHP file is written to a web-accessible directory on the server, outside its intended location, and inadequate cleanup fails to remove it.
6.  The attacker subsequently accesses the newly written malicious PHP file through a direct web request, triggering its execution on the server.
7.  Successful execution of the malicious PHP file leads to remote code execution (RCE) on the underlying server, allowing arbitrary command execution and further system compromise.

## Impact

Successful exploitation of CVE-2026-6101 grants authenticated attackers the ability to write arbitrary files to the web server, potentially leading to full remote code execution (RCE) on the WordPress instance. This can result in complete compromise of the website, including data theft, defacement, or further lateral movement within the hosting environment. While specific victim counts are not provided, WordPress sites utilizing the affected AMP for WP plugin versions are at risk. The CVSS v3.1 Base Score of 7.5 indicates a high severity vulnerability, reflecting the critical consequences of successful exploitation.

## Recommendation

*   Patch CVE-2026-6101 immediately by updating the AMP for WP – Accelerated Mobile Pages plugin to version 1.1.13 or newer.
