---
title: Google Chrome Turbofan Type Confusion Vulnerability (CVE-2026-6301)
slug: 2026-04-chrome-turbofan-type-confusion
description: A type confusion vulnerability in Google Chrome's Turbofan component (CVE-2026-6301) allows a remote attacker to execute arbitrary code within a sandbox by exploiting a crafted HTML page, impacting system integrity and availability.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - type-confusion
  - code-execution
  - chrome
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-6301
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6301
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/495273999
rules:
  - title: Detect Suspicious Script Execution via Chrome
    description: Detects potential exploitation attempts of Chrome vulnerabilities by monitoring for unusual script execution events originating from the Chrome process.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Chrome Network Connection to Suspicious Domains
    description: Detects Chrome making network connections to domains associated with exploit delivery or command and control activity.
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

CVE-2026-6301 describes a type confusion vulnerability affecting the Turbofan component in Google Chrome versions prior to 147.0.7727.101. The vulnerability allows a remote attacker to potentially execute arbitrary code within the Chrome sandbox. The attack is initiated by crafting a malicious HTML page that, when rendered by a vulnerable Chrome browser, triggers the type confusion in Turbofan. Successful exploitation could lead to arbitrary code execution, potentially allowing the attacker to…
