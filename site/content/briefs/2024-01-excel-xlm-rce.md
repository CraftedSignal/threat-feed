---
brief_id: brief-2024-01-03-excel-xlm-rce
event_id: brief-2024-01-03-excel-xlm-rce
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:09d2f61b0eb6da50d978cdfdc24948f94d5ab5b49151db4c50b44f1e9659b9f5
    summary: exploited:true; KEV CVE-2026-32202; KEV CVE-2026-20122; KEV CVE-2025-8088; KEV CVE-2017-0199; KEV CVE-2026-21514
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Microsoft Excel XLM Macro Remote Code Execution on macOS
slug: 2024-01-excel-xlm-rce
description: A logic flaw in Microsoft Excel allows remote code execution on macOS via malicious XLM macros in SYLK files, bypassing the 'Disable all macros without notification' setting.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2021-11-03T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:dtsearch:dtsearch:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:x64:*
  - cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:x86:*
  - cpe:2.3:a:microsoft:office:2007:sp3:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office:2010:sp2:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office:2013:sp1:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office:2016:-:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:-:x64:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:-:x86:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:macos:*:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2024:*:*:*:*:-:x64:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2024:*:*:*:*:-:x86:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2024:*:*:*:*:macos:*:*
  - cpe:2.3:a:philips:intellispace_portal:7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:philips:intellispace_portal:8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_vista:-:sp2:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=289C51DB-789E-5BBC-869B-291AC527B641&utm_source=rss&utm_medium=rss
tags:
  - excel
  - xlm
  - rce
  - macro
  - macos
  - sylk
vendors:
  - Apache
  - Apple
  - Cisco
  - Google
  - Ivanti
  - Linux
  - Marimo
  - Microsoft
  - Mozilla
  - Opera
  - Palo Alto Networks
  - RARLAB
  - WebPros
products:
  - Cisco Catalyst SD-WAN
  - Cisco Catalyst SD-WAN Manager
  - cPanel & WHM
  - EPMM
  - Excel
  - Exchange Server
  - Firefox
  - Google Chrome
  - Internet Explorer
  - Linux Kernel
  - macOS Catalina 10.15
  - Marimo (Python notebooks)
  - Microsoft 365 Apps for Enterprise
  - Microsoft Edge
  - Microsoft Excel
  - Microsoft Office
  - Microsoft Office 2011
  - Microsoft Office 2016
  - Microsoft Office 2019
  - Mozilla Firefox
  - Office LTSC 2021
  - Office LTSC 2024
  - Opera
  - PAN-OS
  - Windows Shell
  - WinRAR
  - WinRAR < 7.13
  - WordPad
  - WP2
product_versions:
  - product: Microsoft 365 Apps for Enterprise
    range: <= 2026-01-26
  - product: Microsoft Office 2016
    range: <= 2026-01-26
  - product: Microsoft Office 2019
    range: <= 2026-01-26
  - product: Office LTSC 2021
    range: <= 2026-01-26
  - product: Office LTSC 2024
    range: <= 2026-01-26
  - product: WinRAR
    range: <= 2025-07
affected_os:
  - macOS Catalina 10.15
  - Windows
  - Linux
cves:
  - id: CVE-2026-21514
    cvss: 7.8
    epss: 0.01517
    kev: true
    kev_status: "true"
  - id: CVE-2026-32202
    cvss: 4.3
    epss: 0.64095
    kev: true
    kev_status: "true"
  - id: CVE-2026-20122
    cvss: 5.4
    epss: 0.07016
    kev: true
    kev_status: "true"
  - id: CVE-2025-8088
    cvss: 8.8
    epss: 0.85778
    kev: true
    kev_status: "true"
  - id: CVE-2017-0199
    cvss: 7.8
    epss: 0.99933
    kev: true
    kev_status: "true"
  - id: CVE-2026-21509
    kev_status: unknown
references:
  - https://objective-see.org/blog/blog_0x50.html
  - https://securelist.com/vulnerabilities-and-exploits-in-q1-2026/119733/
  - https://www.proofpoint.com/us/blog/threat-insight/more-cves-same-playbook-2026-vulnerability-exploitation-wild
  - https://thehackernews.com/2026/06/winrar-flaw-exploited-by-russia-aligned.html
  - https://www.darkreading.com/vulnerabilities-threats/russian-groups-winrar-flaw-ukrainian-orgs
  - https://sploitus.com/exploit?id=289C51DB-789E-5BBC-869B-291AC527B641&utm_source=rss&utm_medium=rss
iocs:
  - type: domain
    value: filen.io
  - type: url
    value: https://sploitus.com/exploit?id=289C51DB-789E-5BBC-869B-291AC527B641
  - type: url
    value: https://sentinelaidefense.com/posts/cve-2026-21509-ole-bypass
ioc_counts:
  domain: 1
  url: 2
rules:
  - title: Detect Suspicious Process Spawned by Excel
    description: Detects suspicious processes spawned by Microsoft Excel, which could indicate exploitation of the XLM macro vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - process_creation
      - macos
  - title: Detect Suspicious XLM Macro CALL Function
    description: Detects the use of the CALL function within XLM macros, which is often used for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    data_sources:
      - file_event
      - macos
  - title: Detect Excel opening SLK files
    description: Detects Excel opening SLK files. This could be an indicator of potential exploitation attempts related to XLM macros.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - macos
rules_count: 3
updates:
  - at: "2026-05-27T08:59:51Z"
    level: L2
    summary: poc_available; added CVE-2026-20122 +3
    sources:
      - proofpoint
  - at: "2026-06-14T08:48:24Z"
    level: L1
    summary: new product
    sources:
      - the-hacker-news
  - at: "2026-06-14T09:28:21Z"
    level: L2
    summary: added CVE-2017-0199 +1
    sources:
      - dark-reading
  - at: "2026-06-30T17:03:32Z"
    level: L2
    summary: microsoft office 2019 version <= 2026-01-26
    sources:
      - sploitus
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-32202; KEV CVE-2026-20122; KEV CVE-2025-8088; KEV CVE-2017-0199; KEV CVE-2026-21514
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

A zero-day vulnerability in Microsoft Excel for macOS allows for remote code execution through the exploitation of XLM macros embedded within SYLK (.slk) files. This vulnerability, originally discovered by Pieter Ceelen of Outflank, bypasses the security setting "Disable all macros without notification," which is intended to prevent automatic macro execution. When this setting is enabled, Excel fails to properly disable XLM macros, leading to their silent execution upon opening a malicious .slk file. While modern macOS features like application sandboxing, file quarantine, and code notarization provide some mitigation, the vulnerability enables an attacker to execute arbitrary code within the context of the Excel process. The exploit has been confirmed on fully patched versions of Microsoft Excel 2016 and 2019 running on macOS Catalina 10.15, posing a significant risk to users who rely on the "Disable all macros without notification" setting for security.

## Attack Chain

1. An attacker crafts a malicious SYLK (.slk) file containing embedded XLM macros.
2. The victim receives the malicious .slk file, often delivered via download.
3. The victim opens the .slk file with Microsoft Excel on macOS.
4. Excel, despite the "Disable all macros without notification" setting, automatically executes the embedded XLM macros without prompting the user.
5. The XLM macro invokes the `CALL` function to execute arbitrary code. For example, `CALL("libc.dylib","system","JC","open -a Calculator")` to launch Calculator.app.
6. The executed code operates within the sandbox of the Microsoft Excel application.
7. Although sandboxed, attacker could attempt to exploit further vulnerabilities to escape the sandbox.
8. The attacker achieves code execution on the target system, potentially leading to further compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on a macOS system without user interaction. While macOS sandboxing, file quarantine, and code notarization mechanisms can limit the impact, a successful exploit could lead to sensitive data compromise, arbitrary code execution, and further system compromise if the attacker can bypass these protections. The impact is somewhat mitigated by macOS security features, but it still presents a viable attack vector.

## Recommendation

*   Enable the "Disable all macros with notification" setting in Microsoft Excel to ensure users are prompted before macro execution, as mentioned in the overview.
*   Monitor for the execution of unusual processes spawned by Microsoft Excel, using the Sigma rule `Detect Suspicious Process Spawned by Excel`.
*   Consider blocking SYLK (.slk) files at the email gateway and web proxy, as recommended by CERT.
*   Implement network monitoring to detect and block connections to known malicious command-and-control servers, to mitigate potential post-exploitation activity.
