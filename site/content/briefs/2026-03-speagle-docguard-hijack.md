---
title: Speagle Malware Hijacks Cobra DocGuard for Data Exfiltration
slug: 2026-03-speagle-docguard-hijack
description: The Speagle malware hijacks the Cobra DocGuard application to exfiltrate sensitive data from infected machines to attacker-controlled Cobra DocGuard servers, effectively masking malicious traffic as legitimate DocGuard communication.
date: "2026-03-21T00:38:59Z"
severities:
  - high
tags:
  - malware
  - data-exfiltration
  - cobra-docguard
  - speagle
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rzdhgg/speagle_malware_hijacks_cobra_docguard_to_steal/
  - https://thehackernews.com/2026/03/speagle-malware-hijacks-cobra-docguard.html?m=1
rules:
  - title: Suspicious Network Connection to Known DocGuard Servers
    description: Detects network connections to known Cobra DocGuard servers from processes other than the legitimate DocGuard client.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: DocGuard Client Spawning Suspicious Child Processes
    description: Detects Cobra DocGuard client spawning suspicious child processes, potentially indicating malware injection or execution.
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

A new malware strain dubbed "Speagle" has been discovered leveraging the legitimate Cobra DocGuard software to exfiltrate sensitive data. This malware infects systems and then uses compromised Cobra DocGuard servers as a C2 to receive stolen data. By masquerading as legitimate DocGuard client-server communication, Speagle seeks to evade detection. First reported in March 2026, the malware represents a sophisticated approach to data theft. The threat actors are exploiting trust in a legitimate…
