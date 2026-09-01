---
title: Detection of MsiExec Web-based Remote Installations
slug: 2026-09-msiexec-web-install
description: Adversaries leverage the Windows Installer service (msiexec.exe) to download and execute malicious MSI packages directly from remote web URLs to facilitate stage-two payload delivery.
date: "2026-09-01T12:20:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - command-and-control
  - windows-installer
  - msiexec
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Adversaries use msiexec to execute malicious code via remote URLs.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The process fetches MSI packages from external URLs.
    confidence_band: high
rules:
  - title: Detect Suspicious MsiExec Remote Web Installation
    description: Detects msiexec.exe process creation with command-line arguments containing web protocols, indicating a remote package download attempt.
    platform: sigma
    severity: medium
    tactics:
      - command-and-control
      - stealth
    techniques:
      - T1105
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy and enable the provided Sigma rule in the SIEM/EDR environment
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search historic process creation logs for msiexec.exe command lines containing 'http' or 'https'
      technique_id: T1218.007
      data_needed:
        - Process creation logs with full command line arguments
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is a known method for remote payload delivery
---

The Windows Installer binary, msiexec.exe, provides functionality to install software from local or network-accessible packages. Adversaries often abuse this legitimate utility by providing a remote URL as a parameter, forcing the process to fetch a malicious Microsoft Installer (MSI) package from an attacker-controlled web server. This technique allows for fileless delivery of second-stage payloads, such as the LokiBot infostealer, by executing code directly within the memory context of the installer process. Defenders should monitor for command-line arguments that include HTTP or HTTPS prefixes combined with calls to msiexec.exe, as this is rarely required for standard administrative software deployment in secure environments.

## Attack Chain

1. Attacker stages a malicious MSI file on an external web server
2. Victim receives a lure (e.g., email attachment or browser-based download) that executes a dropper script
3. Dropper script invokes 'msiexec.exe' via the command line
4. The command line includes a remote URL string pointing to the hosted MSI package
5. MsiExec establishes an outbound network connection to the attacker-controlled host
6. MsiExec downloads the malicious MSI package into a temporary directory
7. Windows Installer service executes the package, which may contain embedded scripts or binaries
8. Final objective (e.g., malware persistence or information theft) is achieved

## Impact

Successful exploitation results in the execution of arbitrary code with the privileges of the invoking user. This has been documented in malware campaigns such as the delivery of LokiBot, which leads to the theft of credentials, exfiltration of sensitive data, and potential lateral movement within the network.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious process executions involving remote URL parameters in the command line. Validate the rule against administrative automation scripts to prevent false positives and tune by allowlisting legitimate internal software distribution servers.

## Tags
- living-off-the-land
- command-and-control
- windows-installer
- msiexec
