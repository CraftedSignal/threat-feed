---
title: Siemens Simcenter Femap Heap-Based Buffer Overflow RCE
slug: 2026-05-siemens-femap-rce
description: A heap-based buffer overflow vulnerability in Siemens Simcenter Femap, tracked as CVE-2025-12659, can be exploited by tricking a user into opening a malicious IPT file, leading to remote code execution.
date: "2026-05-14T15:01:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2025-12659
  - heap overflow
  - remote code execution
  - simcenter femap
  - siemens
  - critical manufacturing
vendors:
  - Siemens
products:
  - Simcenter Femap
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2025-12659
    epss: 0.00016
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-05
  - https://www.cve.org/CVERecord?id=CVE-2025-12659
  - https://support.sw.siemens.com/product/275652363/
rules:
  - title: Detect Suspicious File Opening via Simcenter Femap
    description: Detects potential exploitation of CVE-2025-12659 — suspicious process execution by Simcenter Femap when opening files from untrusted locations
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Femap executing from unusual locations
    description: Detects potential exploitation of CVE-2025-12659 — Femap executed from unusual locations.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A heap-based buffer overflow vulnerability exists in Siemens Simcenter Femap versions prior to 2512.0003. The vulnerability, tracked as CVE-2025-12659, resides in the Datakit library and is triggered when the application parses specially crafted IPT files. An attacker could exploit this vulnerability by enticing a user to open a malicious IPT file with the affected application. Successful exploitation allows an attacker to achieve remote code execution within the context of the current process. Siemens has addressed this vulnerability in Simcenter Femap version 2512.0003 and recommends updating to the latest version to mitigate the risk. The vulnerability was reported by TrendAI Zero Day Initiative.

## Attack Chain

1.  Attacker crafts a malicious IPT file designed to trigger a heap-based buffer overflow in the Datakit library.
2.  The attacker delivers the malicious IPT file to the victim via social engineering or other means (e.g., email attachment, shared drive).
3.  The victim opens the malicious IPT file using a vulnerable version of Siemens Simcenter Femap.
4.  Simcenter Femap parses the malicious IPT file, triggering the heap-based buffer overflow in the Datakit library.
5.  The buffer overflow corrupts memory, allowing the attacker to overwrite critical data or inject malicious code.
6.  The attacker's injected code is executed within the context of the Simcenter Femap process.
7.  The attacker gains control of the affected system.
8.  The attacker performs malicious actions, such as installing malware, stealing data, or pivoting to other systems on the network.

## Impact

Successful exploitation of CVE-2025-12659 allows an attacker to execute arbitrary code on a system running a vulnerable version of Siemens Simcenter Femap. This could lead to complete system compromise, including data theft, modification, or destruction. Given that Simcenter Femap is used in critical manufacturing, a successful attack could disrupt operations, compromise intellectual property, and potentially impact the safety and reliability of industrial processes.

## Recommendation

*   Apply the vendor-provided patch by updating Siemens Simcenter Femap to version V2512.0003 or later to remediate CVE-2025-12659.
*   Deploy the Sigma rule "Detect Suspicious File Opening via Simcenter Femap" to identify potential exploitation attempts.
*   Minimize network exposure for all control system devices and ensure they are not accessible from the internet, as recommended by CISA.
*   Locate control system networks and remote devices behind firewalls and isolate them from business networks, as per CISA recommendations.
