---
title: Compromised Telnyx PyPI Package Distributes Credential-Stealing Malware
slug: 2026-03-telnyx-pypi-compromise
description: A threat actor compromised the PyPI package `telnyx`, uploading malicious versions 4.87.1 and 4.87.2 containing credential-stealing malware that exfiltrates data to a C2 server.
date: "2026-03-30T19:15:30Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: ip
    value: 83.142.209.203
  - type: url
    value: http://83.142.209.203:8080/ringtone.wav
  - type: url
    value: http://83.142.209.203:8080/hangup.wav
  - type: url
    value: http://83.142.209.203:8080/raw
  - type: hash_sha256
    value: 7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9
  - type: hash_sha256
    value: cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3
  - type: hash_sha256
    value: 4eceb569b4330565b93058465beab0e6d5ea09cfba8e7f29d7be1b5a2abd958a
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

On March 27, 2026, the `telnyx` Python package on PyPI was compromised by TeamPCP, resulting in the distribution of malicious versions 4.87.1 and 4.87.2. The attacker, having gained unauthorized access to PyPI credentials, bypassed the legitimate GitHub release pipeline to upload these compromised packages directly. These versions contain malware designed to harvest sensitive credentials from infected systems and exfiltrate them to a command-and-control (C2) server. The malicious packages were available for approximately 6 hours before being quarantined by PyPI. Version 4.87.1 contained a typo preventing execution, making 4.87.2 the fully functional malicious version. This incident highlights the risk of supply chain attacks targeting open-source package repositories, potentially affecting any system that installed the `telnyx` package during the exposure window.

## Attack Chain

1.  The attacker gains unauthorized access to PyPI credentials for the `telnyx` package.
2.  The attacker uploads malicious versions 4.87.1 and 4.87.2 of the `telnyx` package to PyPI, bypassing the legitimate GitHub repository.
3.  When a user installs or upgrades to the malicious `telnyx` package, the injected malware within `telnyx/_client.py` executes upon importing the library (`import telnyx`).
4.  On Linux/macOS systems, the malware spawns a detached subprocess to ensure persistence and downloads a payload hidden inside a WAV audio file (`ringtone.wav`) from the C2 server at `http://83.142.209.203:8080/`.
5.  The downloaded payload harvests sensitive credentials, including SSH keys, AWS/GCP/Azure credentials, Kubernetes tokens, Docker configurations, .env files, database credentials, and crypto wallets.
6.  If Kubernetes access is detected, the malware deploys privileged pods to all nodes for lateral movement within the Kubernetes cluster.
7.  The collected data is encrypted using AES-256-CBC and RSA-4096, then exfiltrated to the C2 server, identified by the header `X-Filename: tpcp.tar.gz`.
8.  On Windows, a binary payload hidden in `hangup.wav` is downloaded from `http://83.142.209.203:8080/`, dropped as `msbuild.exe` in the Startup folder for persistence, and executed with a hidden window, polling the endpoint `http://83.142.209.203:8080/raw`.

## Impact

The compromise of the `telnyx` PyPI package poses a significant risk to developers and organizations that use the library.  Successful exploitation leads to the theft of sensitive credentials, potentially granting the attacker unauthorized access to critical infrastructure, cloud resources, and sensitive data. TeamPCP's previous campaign against LiteLLM and the similarities in this attack suggest a pattern of targeting open-source projects to infiltrate developer environments and steal secrets.  The impact includes potential data breaches, financial losses, and reputational damage. The exposure window was approximately 6 hours during which vulnerable versions were available.

## Recommendation

*   Immediately check for the presence of malicious `telnyx` package versions (4.87.1 or 4.87.2) in your environment using the provided commands and uninstall them (`pip uninstall telnyx`).
*   Due to the credential-stealing nature of the malware, rotate all potentially exposed secrets, including SSH keys, cloud provider credentials (AWS, GCP, Azure), Kubernetes tokens, Docker registry credentials, database passwords, API keys in .env files, and Telnyx API keys.
*   Check for persistence mechanisms used by the malware, specifically the `audiomon` service and associated files on Linux/macOS, and the `msbuild.exe` executable in the Startup folder on Windows, based on the file paths provided in the "Filesystem" section.
*   Block the identified C2 IP address (`83.142.209.203`) and payload URLs (`http://83.142.209.203:8080/ringtone.wav`, `http://83.142.209.203:8080/hangup.wav`, `http://83.142.209.203:8080/raw`) at your network perimeter.
*   Deploy the following Sigma rule to detect the creation of `msbuild.exe` in the Startup folder.
*   Pin the `telnyx` package to the safe version 4.87.0 in your project dependencies to prevent future installations of compromised versions.
