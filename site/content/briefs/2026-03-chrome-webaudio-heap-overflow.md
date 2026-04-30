---
title: Google Chrome WebAudio Heap Buffer Overflow Vulnerability (CVE-2026-4673)
slug: 2026-03-chrome-webaudio-heap-overflow
description: A remote attacker can exploit a heap buffer overflow vulnerability (CVE-2026-4673) in Google Chrome's WebAudio component before version 146.0.7680.165 by crafting a malicious HTML page, potentially leading to an out-of-bounds memory write and arbitrary code execution.
date: "2026-03-25T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4673
  - chrome
  - webaudio
  - heap overflow
  - code execution
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4673
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/485397284
rules:
  - title: Detect Chrome WebAudio Exploitation via Process Creation
    description: Detects suspicious process creation events potentially related to Chrome WebAudio exploitation. It looks for unusual child processes spawned by Chrome.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053.005
      - T1059.001
      - T1059.003
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Chrome WebAudio Exploitation via Network Connection
    description: Detects suspicious outbound network connections initiated by Chrome, potentially indicating command and control activity after a WebAudio exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-4673 is a heap buffer overflow vulnerability affecting the WebAudio component of Google Chrome. The vulnerability exists in versions prior to 146.0.7680.165. A remote attacker could exploit this vulnerability by crafting a malicious HTML page designed to trigger an out-of-bounds memory write. The Chromium security team has rated this vulnerability as High severity. Successful exploitation could allow an attacker to potentially execute arbitrary code within the context of the Chrome…
