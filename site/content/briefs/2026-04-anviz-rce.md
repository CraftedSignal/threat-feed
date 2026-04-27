---
title: Anviz CX2 Lite and CX7 Unauthenticated Remote Code Execution via Unverified Update Packages (CVE-2026-40066)
slug: 2026-04-anviz-rce
description: Anviz CX2 Lite and CX7 devices are vulnerable to unverified update packages that allow for unauthenticated remote code execution by unpacking and executing a malicious script.
date: "2026-04-17T20:16:35Z"
severities:
  - critical
tags:
  - cve-2026-40066
  - rce
  - iot
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1205
    technique_name: Traffic Signaling
cves:
  - id: CVE-2026-40066
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40066
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.anviz.com/contact-us.html
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
rules:
  - title: Detect Network Connection to Anviz Device for Firmware Update
    description: Detects network connections to Anviz devices attempting to download firmware updates, which could indicate exploitation of CVE-2026-40066
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1205
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Process Creation on Anviz Device
    description: Detects suspicious process creation on Anviz devices, such as execution of shell scripts or unusual binaries, indicating potential RCE
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Anviz CX2 Lite and CX7 devices are susceptible to a critical vulnerability (CVE-2026-40066) stemming from the lack of integrity checks on update packages. An attacker can upload a crafted update package to the device. The vulnerable devices then unpack the contents of this package and execute a script without proper authentication or verification. This leads to unauthenticated remote code execution, potentially allowing the attacker to gain complete control over the compromised device. The…
