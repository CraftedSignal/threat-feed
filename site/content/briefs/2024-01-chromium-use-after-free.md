---
title: Chromium Use-After-Free Vulnerability in GPU Component (CVE-2026-7357)
slug: 2024-01-chromium-use-after-free
description: CVE-2026-7357 is a use-after-free vulnerability in the GPU component of Chromium that also affects Microsoft Edge, potentially leading to arbitrary code execution.
date: "2026-05-01T02:21:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - use-after-free
  - chromium
  - edge
  - chrome
vendors:
  - Google
  - Microsoft
products:
  - Chrome
  - Edge
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-7357
    cvss: 7.5
    epss: 0.00011
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7357
  - https://chromereleases.googleblog.com/2025
rules:
  - title: Detect Suspicious WebAssembly Execution
    description: Detects the execution of WebAssembly code, which could be used to exploit browser vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Edge with Suspicious CommandLine
    description: Detects Edge browser running with suspicious command line arguments often seen in exploit PoCs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-7357 is a critical use-after-free vulnerability residing within the GPU component of the Chromium rendering engine. This flaw directly impacts Google Chrome and, due to Microsoft Edge's reliance on Chromium, also affects Edge users. A remote attacker could potentially exploit this vulnerability to execute arbitrary code on a targeted system. The vulnerability stems from improper memory management within the GPU processing routines. While the specific exploitation details are not provided in this brief, successful exploitation generally involves crafting malicious web content to trigger the vulnerability during GPU operations.

## Attack Chain

1.  Attacker crafts a malicious HTML page containing JavaScript that triggers specific GPU functions.
2.  User visits the malicious website using Chrome or Edge.
3.  The browser's rendering engine processes the malicious JavaScript, leading to the allocation and subsequent freeing of a memory region in the GPU component.
4.  The attacker's JavaScript code then attempts to access the previously freed memory region, triggering the use-after-free vulnerability.
5.  By manipulating the memory layout, the attacker can overwrite the freed memory with controlled data.
6.  The overwritten memory is later accessed by the GPU, leading to the execution of attacker-controlled code.
7.  The attacker gains arbitrary code execution within the context of the browser process.
8.  The attacker leverages the code execution to escalate privileges or perform other malicious activities.

## Impact

Successful exploitation of CVE-2026-7357 can lead to arbitrary code execution on the victim's machine. The attacker could potentially install malware, steal sensitive data, or take control of the affected system. Given the widespread use of Chrome and Edge, this vulnerability poses a significant risk to a large number of users.

## Recommendation

*   Apply the latest security updates for Google Chrome to address CVE-2026-7357.
*   Apply the latest security updates for Microsoft Edge to address CVE-2026-7357.
*   Deploy the Sigma rule "Detect Suspicious WebAssembly Execution" to identify potential exploitation attempts involving WebAssembly.
