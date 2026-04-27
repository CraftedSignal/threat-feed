---
title: Compromised Telnyx PyPI Package Distributes Credential-Stealing Malware
slug: 2026-03-telnyx-pypi-compromise
description: A threat actor compromised the PyPI package `telnyx`, uploading malicious versions 4.87.1 and 4.87.2 containing credential-stealing malware that exfiltrates data to a C2 server.
date: "2026-03-30T19:15:30Z"
severities:
  - critical
actors:
  - TeamPCP
tags:
  - supply-chain
  - pypi
  - credential-theft
  - teampcp
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://github.com/advisories/GHSA-955r-262c-33jc
  - https://github.com/team-telnyx/telnyx-python/issues/235
  - https://www.endorlabs.com/learn/teampcp-strikes-again-telnyx-compromised-three-days-after-litellm
  - https://ramimac.me/teampcp
ioc_counts:
  hash_sha256: 3
  ip: 1
  url: 3
rules:
  - title: Detect MsBuild.exe in Startup Folder (Telnyx Compromise)
    description: Detects the creation of msbuild.exe in the Startup folder, a persistence mechanism used in the compromised Telnyx package attack.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Network Connection to Telnyx Compromise C2
    description: Detects network connections to the C2 IP address (83.142.209.203) used in the compromised Telnyx package attack.
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

On March 27, 2026, the `telnyx` Python package on PyPI was compromised by TeamPCP, resulting in the distribution of malicious versions 4.87.1 and 4.87.2. The attacker, having gained unauthorized access to PyPI credentials, bypassed the legitimate GitHub release pipeline to upload these compromised packages directly. These versions contain malware designed to harvest sensitive credentials from infected systems and exfiltrate them to a command-and-control (C2) server. The malicious packages were…
