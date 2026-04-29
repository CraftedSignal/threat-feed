---
title: TeamPCP Backdoors Telnyx PyPI Package with Steganographic Malware
slug: 2026-03-teampcp-telnyx
description: The TeamPCP threat actor compromised the Telnyx PyPI package, injecting credential-stealing malware hidden within WAV audio files to target Linux, macOS, and Windows systems.
date: "2026-03-28T12:00:00Z"
type: coverage
types:
  - coverage
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

On March 27, 2026, the Telnyx package on the Python Package Index (PyPI) was compromised by the threat actor TeamPCP. Malicious versions 4.87.1 and 4.87.2 were uploaded, containing credential-stealing malware concealed within WAV audio files. This supply-chain attack targeted developers using the Telnyx Python SDK, a popular package with over 740,000 monthly downloads, used for integrating communication services into applications. The malicious code resides in the `telnyx/_client.py` file and executes upon import. The compromise is believed to have originated from stolen credentials for the publishing account on the PyPI registry. TeamPCP has been linked to previous supply-chain attacks and wiper campaigns against Iranian systems, highlighting the group's focus on disrupting software development and infrastructure.

## Attack Chain

1. TeamPCP gains unauthorized access to the Telnyx PyPI account, likely through credential theft.
2. Malicious versions 4.87.1 and 4.87.2 of the Telnyx package are published to PyPI.
3. When a developer installs the compromised Telnyx package, the `telnyx/_client.py` file is executed upon import.
4. On Linux and macOS, a detached process is spawned to download a second-stage payload disguised as a WAV audio file (`ringtone.wav`) from a remote command-and-control (C2) server.
5. Steganography is used to hide malicious code within the WAV file's data frames.
6. The embedded payload is extracted using an XOR-based decryption routine and executed in memory.
7. The malware harvests sensitive data, including SSH keys, credentials, cloud tokens, cryptocurrency wallets, and environment variables.
8. If Kubernetes is present, the malware enumerates cluster secrets and deploys privileged pods to access underlying host systems. On Windows, a different WAV file (`hangup.wav`) is downloaded that extracts and saves an executable named `msbuild.exe` to the startup folder for persistence.

## Impact

This supply chain attack could result in widespread compromise of systems utilizing the Telnyx Python SDK. Over 740,000 monthly downloads indicate a large potential victim pool. Stolen credentials and secrets can lead to unauthorized access to cloud resources, sensitive data exfiltration, and further lateral movement within compromised networks. For systems running Kubernetes, the attacker could gain control over the entire cluster, leading to significant disruption and data loss. Developers who installed the malicious packages are advised to consider their systems fully compromised and rotate all secrets as soon as possible.

## Recommendation

*   Identify and remove Telnyx versions 4.87.1 and 4.87.2 from all environments, reverting to version 4.87.0 as recommended by the vendor.
*   Monitor network connections for processes spawned by Python interpreters (`python.exe`, `python3`) attempting to download files with the `.wav` extension, using the "Detect Suspicious Python WAV Download" Sigma rule provided below.
*   Implement stricter controls and multi-factor authentication for PyPI accounts used to publish packages to prevent similar supply chain attacks.
*   Deploy the "Detect msbuild.exe in Startup Folder" Sigma rule to identify potential persistence attempts on Windows systems.
*   Rotate all secrets and credentials on any system that has imported the malicious Telnyx package.
