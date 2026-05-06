---
title: Google Chrome FedCM Use-After-Free Vulnerability (CVE-2026-4680)
slug: 2026-03-chrome-fedcm-uaf
description: A use-after-free vulnerability in Google Chrome's FedCM component (CVE-2026-4680) allows a remote attacker to execute arbitrary code within a sandbox by exploiting a crafted HTML page.
date: "2026-03-24T01:17:03Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-4680
  - use-after-free
  - chrome
  - fedcm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4680
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/491869946
rules:
  - title: Detect Suspicious Chrome Process Argument
    description: Detects potentially malicious Chrome processes based on command-line arguments often used in exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Chrome Process Argument Linux
    description: Detects potentially malicious Chrome processes on Linux based on command-line arguments often used in exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A use-after-free vulnerability, identified as CVE-2026-4680, exists in the FedCM implementation of Google Chrome. This flaw affects versions prior to 146.0.7680.165. Exploitation is possible by a remote attacker who crafts a malicious HTML page. Successful exploitation allows for arbitrary code execution within the Chrome sandbox, potentially leading to further compromise. The Chromium security team has rated this vulnerability as High severity. This issue impacts users across Windows, Linux…
