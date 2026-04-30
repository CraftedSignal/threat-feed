---
title: Firefox and Thunderbird Sandbox Escape Vulnerability (CVE-2026-4687)
slug: 2026-03-firefox-sandbox-escape
description: CVE-2026-4687 is a sandbox escape vulnerability in Firefox and Thunderbird due to incorrect boundary conditions in the Telemetry component, potentially allowing an attacker to execute arbitrary code outside the sandbox.
date: "2026-03-24T13:16:04Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - sandbox-escape
  - firefox
  - thunderbird
  - cve-2026-4687
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4687
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2016368
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-21/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Firefox/Thunderbird Telemetry Sandbox Escape Attempt
    description: Detects potential exploitation attempts of CVE-2026-4687 by monitoring for unusual process behavior originating from Firefox or Thunderbird related to telemetry.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Firefox/Thunderbird Unusual Network Connection via Telemetry
    description: Detects potential exploitation attempts of CVE-2026-4687 by monitoring for unusual network connections originating from Firefox or Thunderbird related to telemetry.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-4687 is a critical sandbox escape vulnerability affecting Mozilla Firefox and Thunderbird. The vulnerability stems from incorrect boundary conditions within the Telemetry component. Specifically, Firefox versions prior to 149, Firefox ESR versions prior to 115.34 and 140.9, and Thunderbird versions prior to 149 and 140.9 are affected. Successful exploitation could allow an attacker to bypass the intended security restrictions of the sandbox environment and potentially execute arbitrary…
