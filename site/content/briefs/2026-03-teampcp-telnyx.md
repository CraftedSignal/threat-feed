---
title: TeamPCP Backdoors Telnyx PyPI Package with Steganographic Malware
slug: 2026-03-teampcp-telnyx
description: The TeamPCP threat actor compromised the Telnyx PyPI package, injecting credential-stealing malware hidden within WAV audio files to target Linux, macOS, and Windows systems.
date: "2026-03-28T12:00:00Z"
severities:
  - critical
actors:
  - TeamPCP
tags:
  - supply chain attack
  - pypi
  - credential theft
  - steganography
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://www.bleepingcomputer.com/news/security/backdoored-telnyx-pypi-package-pushes-malware-hidden-in-wav-audio/
rules:
  - title: Detect Suspicious Python WAV Download
    description: Detects Python processes downloading WAV files, which is indicative of the TeamPCP Telnyx supply chain attack.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - supply_chain
    techniques:
      - T1105
    data_sources:
      - network_connection
      - windows
  - title: Detect msbuild.exe in Startup Folder
    description: Detects the presence of msbuild.exe in the Windows Startup folder, indicating persistence established by the TeamPCP malware.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - supply_chain
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On March 27, 2026, the Telnyx package on the Python Package Index (PyPI) was compromised by the threat actor TeamPCP. Malicious versions 4.87.1 and 4.87.2 were uploaded, containing credential-stealing malware concealed within WAV audio files. This supply-chain attack targeted developers using the Telnyx Python SDK, a popular package with over 740,000 monthly downloads, used for integrating communication services into applications. The malicious code resides in the `telnyx/_client.py` file and…
