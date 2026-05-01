---
title: Chromium Use-After-Free Vulnerability in Media Component (CVE-2026-7355)
slug: 2026-05-chromium-uaf
description: CVE-2026-7355 is a use-after-free vulnerability in the Media component of Chromium, affecting Google Chrome and Microsoft Edge, potentially allowing for arbitrary code execution.
date: "2026-05-01T02:21:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - use-after-free
  - chromium
  - cve-2026-7355
  - browser
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
  - id: CVE-2026-7355
    cvss: 8.8
    epss: 0.00038
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7355
  - https://chromereleases.googleblog.com/2025
rules:
  - title: Detect Chromium Use-After-Free in Media Component
    description: Detects potential exploitation attempts of the Chromium use-after-free vulnerability (CVE-2026-7355) based on suspicious process execution patterns after browser events.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Creation by Browser Processes
    description: Detects creation of executable files by browser processes, potentially indicating exploitation of a vulnerability like CVE-2026-7355.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-7355 is a critical use-after-free vulnerability residing in the Media component of the Chromium browser engine. This vulnerability affects Google Chrome and Microsoft Edge, as Edge incorporates Chromium. A use-after-free vulnerability occurs when an application attempts to use memory after it has been freed, which can lead to crashes, arbitrary code execution, or other unexpected behavior. Successful exploitation could allow an attacker to execute arbitrary code within the context of the browser. This vulnerability was reported and patched by the Chromium project.

## Attack Chain

1.  An attacker crafts a malicious webpage containing specially crafted media content.
2.  A user opens the malicious webpage in a vulnerable version of Chrome or Edge.
3.  The browser attempts to process the malicious media content, triggering the use-after-free vulnerability in the Media component.
4.  The vulnerable code attempts to access a freed memory region.
5.  The attacker gains control of the memory region due to the use-after-free condition.
6.  The attacker injects malicious code into the controlled memory region.
7.  The browser executes the attacker-controlled code.
8.  The attacker achieves arbitrary code execution within the context of the browser process, potentially leading to system compromise.

## Impact

Successful exploitation of CVE-2026-7355 can lead to arbitrary code execution within the context of the browser process. An attacker could potentially gain control of the user's system, steal sensitive information, or install malware. Given the widespread use of Chrome and Edge, a successful exploit could impact a large number of users across various sectors.

## Recommendation

*   Apply the latest security updates for Google Chrome and Microsoft Edge to patch CVE-2026-7355.
*   Deploy the Sigma rule "Detect Chromium Use-After-Free in Media Component" to identify potential exploitation attempts.
*   Enable process creation logging to capture events related to potential exploitation attempts, facilitating detection rule functionality.
