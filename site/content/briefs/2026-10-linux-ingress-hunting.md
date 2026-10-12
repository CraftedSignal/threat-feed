---
title: Detection of Linux Ingress Tool Transfer via Curl and Wget
slug: 2026-10-linux-ingress-hunting
description: This brief outlines the monitoring of curl and wget execution on Linux systems to detect the ingress of malicious tools, a common technique employed by adversaries for payload delivery and post-compromise activity.
date: "2026-10-12T17:50:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - hunting
  - ingress-tool-transfer
  - linux
  - edr
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This activity is significant as 'curl' and 'wget' are commonly used for downloading files, which can indicate potential ingress of malicious tools.
    confidence_band: high
rules:
  - title: Detect Linux Ingress Tool Transfer via Curl or Wget
    description: Detects the execution of curl or wget, which may indicate the ingress of malicious files or tools.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection for curl and wget execution to identify potential ingress tool transfers.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided by Splunk-ESCU for T1105.
  hunt_leads:
    - lead: Search for curl/wget executions with unusual command-line parameters (e.g., -o, -O, -k, --no-check-certificate) in logs.
      technique_id: T1105
      data_needed:
        - Process command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Commonly associated with downloader activity.
---

Adversaries frequently leverage legitimate Linux binaries, specifically 'curl' and 'wget', to facilitate the transfer of malicious payloads or secondary tools into a compromised environment. This technique, classified under Ingress Tool Transfer (MITRE ATT&CK T1105), allows actors to bridge the gap between initial access and follow-on malicious activity such as code execution, persistence, or data exfiltration.

Security operations teams must baseline these utilities to differentiate between routine administrative or automated system tasks and potentially malicious downloads. While these binaries are ubiquitous in Linux environments, their usage by non-privileged accounts or in unusual execution chains provides high-value signals for hunting and incident response. This detection focus is essential for identifying threats associated with supply chain compromises, botnet propagation (e.g., XorDDos), and other living-off-the-land scenarios where attackers attempt to minimize their footprint by utilizing pre-installed system tools.

## Impact

Successful exploitation of ingress tool transfer allows attackers to introduce custom malware, reverse shells, or remote access trojans into a network. This can lead to full system compromise, exfiltration of sensitive organizational data, and long-term persistence. Unauthorized code execution resulting from these downloads often serves as a pivot point for lateral movement within the Linux infrastructure.

## Recommendation

* Deploy process-creation monitoring to capture command-line arguments for 'curl' and 'wget' using Sysmon for Linux EventID 1 or equivalent EDR telemetry.
* Baseline common execution paths and parent processes for these utilities to establish a normal operational profile for your environment.
* Implement the provided Sigma rule in your SIEM to flag non-standard execution of file-download utilities.
* Prioritize the investigation of downloads originating from unknown or suspicious external IP addresses, especially when executed by user accounts that do not typically perform administrative tasks.
