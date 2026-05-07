---
title: Microsoft Excel XLM Macro Remote Code Execution on macOS
slug: 2024-01-excel-xlm-rce
description: A logic flaw in Microsoft Excel allows remote code execution on macOS via malicious XLM macros in SYLK files, bypassing the 'Disable all macros without notification' setting.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - excel
  - xlm
  - rce
  - macro
  - macos
  - sylk
vendors:
  - Microsoft
  - Apple
products:
  - Excel
  - Microsoft Excel
  - Microsoft Office 2019
  - Microsoft Office 2011
  - macOS Catalina 10.15
affected_os:
  - macOS Catalina 10.15
references:
  - https://objective-see.org/blog/blog_0x50.html
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
---

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
