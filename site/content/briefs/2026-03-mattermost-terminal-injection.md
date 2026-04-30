---
title: Mattermost mmctl Terminal Injection Vulnerability (CVE-2026-3108)
slug: 2026-03-mattermost-terminal-injection
description: Mattermost versions 11.2.x <= 11.2.2, 10.11.x <= 10.11.10, 11.4.x <= 11.4.0, 11.3.x <= 11.3.1 are vulnerable to terminal injection, allowing attackers to manipulate administrator terminals via crafted messages containing ANSI and OSC escape sequences.
date: "2026-03-26T17:16:41Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-3108
  - mattermost
  - terminal-injection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3108
  - https://mattermost.com/security-updates
rules:
  - title: Detect Suspicious ANSI Escape Sequences in Mattermost Logs
    description: Detects the presence of ANSI escape sequences in Mattermost logs, potentially indicating an attempt to exploit CVE-2026-3108.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect OSC Escape Sequences in Mattermost Logs
    description: Detects the presence of OSC escape sequences (used for clipboard manipulation) in Mattermost logs, potentially indicating an attempt to exploit CVE-2026-3108.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-3108 affects Mattermost servers using the `mmctl` command-line tool. This vulnerability, disclosed in March 2026, stems from a failure to properly sanitize user-controlled post content within the terminal output of `mmctl` commands. Specifically, versions 11.2.x up to 11.2.2, 10.11.x up to 10.11.10, 11.4.x up to 11.4.0, and 11.3.x up to 11.3.1 are susceptible. An attacker leveraging this flaw can inject ANSI and OSC escape sequences into administrator terminals. These sequences enable…
