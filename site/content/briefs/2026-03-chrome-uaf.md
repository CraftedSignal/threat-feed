---
title: Google Chrome Use-After-Free Vulnerability (CVE-2026-4676)
slug: 2026-03-chrome-uaf
description: A use-after-free vulnerability (CVE-2026-4676) in Google Chrome before 146.0.7680.165 allows a remote attacker to potentially perform a sandbox escape via a crafted HTML page.
date: "2026-03-24T01:17:03Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - use-after-free
  - sandbox-escape
  - chrome
  - cve-2026-4676
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4676
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/488613135
rules:
  - title: Detect Chrome Sandbox Escape Attempt
    description: Detects potential attempts to escape the Chrome sandbox by monitoring for unusual child processes spawned by Chrome renderers.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Creation by Chrome Renderer
    description: Detects file creation events by chrome renderers to unusual locations, potentially indicative of sandbox escape attempts
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-4676 is a use-after-free vulnerability affecting Google Chrome versions prior to 146.0.7680.165. This flaw resides within the Dawn component of Chrome and can be triggered by a remote attacker who crafts a malicious HTML page. Successful exploitation could lead to a sandbox escape, granting the attacker elevated privileges within the system. This vulnerability was patched in the March 23, 2026 stable channel update for desktop. The vulnerability affects users on Windows, Linux, and…
