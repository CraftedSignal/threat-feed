---
title: Windows Peripheral Device Discovery via fsutil
slug: 2024-01-02-peripheral-device-discovery
description: Adversaries may use the Windows file system utility, fsutil.exe, with the fsinfo drives command to enumerate attached peripheral devices and gain information about a compromised system.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - windows
  - fsutil
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1120
    technique_name: Peripheral Device Discovery
references:
  - https://attack.mitre.org/techniques/T1120/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_peripheral_device.toml
rules:
  - title: Detect Peripheral Device Discovery via fsutil.exe
    description: Detects the execution of fsutil.exe with arguments related to peripheral device discovery.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1120
    data_sources:
      - process_creation
      - windows
  - title: Detect Peripheral Device Discovery via fsutil.exe (PE Original Filename)
    description: Detects the execution of fsutil.exe by checking the PE original filename for obfuscated execution.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1120
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may leverage native operating system tools like `fsutil.exe` to perform reconnaissance activities within a compromised environment. The `fsutil fsinfo drives` command provides information about connected drives, including removable media, mapped network drives, and backup locations. Discovery of these devices can help adversaries identify valuable data stores for exfiltration or encryption as part of a broader attack campaign. This command can be run interactively or via automated scripts, making it a versatile tool for post-exploitation activities. Defenders should monitor for unusual execution of `fsutil` with the `fsinfo drives` arguments, particularly when executed by non-administrative users or from unusual locations.

## Attack Chain

1.  An attacker gains initial access to a Windows system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker executes `fsutil.exe` via command line or script.
3.  The `fsutil` command uses the `fsinfo` subcommand.
4.  The `fsinfo` subcommand uses the `drives` argument to list connected drives.
5.  The system returns a list of attached drives and their types (e.g., local, network, removable).
6.  The attacker analyzes the output to identify potentially valuable targets.
7.  The attacker moves laterally to access identified drives.
8.  The attacker exfiltrates sensitive data or deploys ransomware on the identified drives.

## Impact

Successful discovery of peripheral devices can lead to the identification of backup locations, mapped network drives, and removable media containing sensitive information. This information enables attackers to expand their reach within the compromised environment and increase the potential for data theft, encryption, or destruction. The low severity reflects the fact that this activity on its own is simply reconnaissance; the actual damage comes from subsequent actions.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious execution of `fsutil.exe` (see below).
*   Enable process creation logging with command line arguments to capture `fsutil` executions (see setup instructions in the Overview).
*   Investigate any process executions of `fsutil.exe` where the parent process is unexpected or the user context is unusual (see Triage and Analysis).
