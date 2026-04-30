---
title: ABB PCM600 Path Traversal Vulnerability (CVE-2018-1002208)
slug: 2026-04-abb-pcm600-path-traversal
description: A path traversal vulnerability in ABB PCM600 versions 1.5 to 2.13 (CVE-2018-1002208) allows a local attacker with low privileges to execute arbitrary code by sending a specially crafted message to the system node.
date: "2026-04-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - path traversal
  - industrial control system
vendors:
  - ABB
products:
  - ABB PCM600
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
cves:
  - id: CVE-2018-1002208
    cvss: 5.5
    epss: 0.00605
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02
  - https://www.cve.org/CVERecord?id=CVE-2018-1002208
  - https://search.abb.com/library/Download.aspx?DocumentID=2NGA002813&amp;LanguageCode=en&amp;DocumentPartId=pdf&amp;Action=Launch
  - https://psirt.abb.com/csaf/2025/2nga002813.json
rules:
  - title: Detect Suspicious File Creation in ABB PCM600 Directories
    description: Detects potential path traversal attempts in ABB PCM600 by monitoring file creation in sensitive directories.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - file_event
      - windows
  - title: Detect ABB PCM600 Process Launching Unexpected Executables
    description: Detects potential exploitation of ABB PCM600 by monitoring for the process launching executables from unusual locations.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

ABB PCM600 versions 1.5 through 2.13 are vulnerable to a path traversal flaw (CVE-2018-1002208) within the SharpZip.dll library. Successful exploitation enables a local attacker with low privileges to execute arbitrary code on the affected system. This vulnerability resides in the software used to configure and manage protection and control IEDs (Intelligent Electronic Devices) in critical infrastructure sectors, specifically critical manufacturing. ABB recommends updating to PCM600 version 2.14 to remediate this vulnerability. The vulnerability was reported to CISA by ABB PSIRT.

## Attack Chain

1.  Attacker gains low-privilege access to the target system running a vulnerable ABB PCM600 version.
2.  The attacker crafts a malicious message containing a path traversal payload designed to exploit CVE-2018-1002208.
3.  The attacker sends the crafted message to the system node, targeting the vulnerable SharpZip.dll.
4.  The SharpZip.dll processes the message without properly sanitizing the provided path.
5.  The path traversal vulnerability allows the attacker to write arbitrary files to locations outside the intended directory.
6.  The attacker leverages the file write capability to place a malicious executable or library in a trusted location.
7.  The attacker triggers the execution of the malicious code, achieving arbitrary code execution on the system.
8.  The attacker can then perform actions such as escalating privileges, installing malware, or disrupting industrial processes.

## Impact

Successful exploitation of CVE-2018-1002208 can lead to arbitrary code execution on systems running vulnerable ABB PCM600 versions within critical manufacturing environments. While no specific victim counts or sectors are detailed in the advisory, the vulnerability's presence in industrial control systems poses a significant risk. A successful attack could disrupt manufacturing processes, cause equipment damage, or lead to data breaches.

## Recommendation

*   Upgrade to ABB Protection and control IED manager PCM600 version 2.14 to address CVE-2018-1002208 as per the vendor's recommendation.
*   If using RE_630 protection relays with older PCM600 versions, implement system-level defenses as described in ABB's security advisory 2NGA002813.
*   Minimize network exposure for all control system devices and systems, ensuring they are not accessible from the internet, as recommended by CISA.
*   Monitor file creation events for suspicious file paths that may indicate path traversal attempts exploiting CVE-2018-1002208, using a rule similar to the example provided.
