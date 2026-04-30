---
title: Google Chrome WebGPU Use-After-Free Vulnerability (CVE-2026-4678)
slug: 2026-03-chrome-webgpu-uaf
description: A use-after-free vulnerability in Google Chrome's WebGPU component (CVE-2026-4678) allows a remote attacker to execute arbitrary code within a sandbox by crafting a malicious HTML page, affecting Chrome versions prior to 146.0.7680.165.
date: "2026-03-24T01:17:03Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-4678
  - use-after-free
  - chrome
  - webgpu
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4678
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/491164019
rules:
  - title: Detect Chrome WebGPU Use-After-Free Exploit Attempt
    description: Detects potential attempts to exploit the Chrome WebGPU use-after-free vulnerability (CVE-2026-4678) by looking for suspicious patterns in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Web Requests Targeting Chrome
    description: Detects suspicious web requests potentially related to Chrome exploits by looking for unusual user agents and request patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4678 is a use-after-free vulnerability impacting Google Chrome versions earlier than 146.0.7680.165. The vulnerability resides within the WebGPU component, a modern graphics API. An unauthenticated, remote attacker can exploit this flaw by enticing a user to open a specially crafted HTML page. Successful exploitation allows the attacker to execute arbitrary code inside the Chrome sandbox. The Chromium project rates this as a High severity issue due to the potential for arbitrary code…
