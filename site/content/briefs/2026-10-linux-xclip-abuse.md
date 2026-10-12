---
title: Abuse of Linux xclip for Clipboard Data Interception
slug: 2026-10-linux-xclip-abuse
description: Adversaries leverage the Linux xclip command-line utility to intercept or exfiltrate sensitive information stored in the system clipboard.
date: "2026-10-12T17:50:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - clipboard-collection
  - linux-security
  - e-r-d-telemetry
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1115
    technique_name: Clipboard Data
    evidence: The following analytic detects the use of the Linux 'xclip' command to copy data from the clipboard.
    confidence_band: high
rules:
  - title: Detect Suspicious Linux Clipboard Access via xclip
    description: Detects the use of the xclip command with arguments commonly used to read or manipulate clipboard data, which may indicate data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1115
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for xclip monitoring
  hunt_leads:
    - lead: Search for historical process creation events involving xclip
      technique_id: T1115
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: xclip is a common indicator of manual or automated clipboard collection
---

This detection brief addresses the use of the 'xclip' utility on Linux systems by threat actors. 'xclip' is a command-line interface that allows for the manipulation of the X11 clipboard. Adversaries utilize this legitimate tool to perform unauthorized collection of sensitive data, such as plaintext passwords, API keys, or IP addresses that users may have copied during their routine administrative or development activities. This technique, identified as T1115 (Clipboard Data) in the MITRE ATT&CK framework, is a common component of Living off the Land (LotL) strategies. By monitoring process execution logs for specific 'xclip' command-line arguments, security operations centers can identify instances where clipboard contents are being read, written, or exfiltrated, enabling early detection of potential credential theft or reconnaissance activity.

## Attack Chain

1. Attacker gains initial access to a Linux endpoint through exploitation of a web vulnerability or compromised credentials.
2. Attacker performs local enumeration to identify user activity, including checking for active X11 sessions.
3. Attacker identifies sensitive information within the user's clipboard that may have been copied from a password manager or a configuration file.
4. Attacker executes the 'xclip' binary with arguments (such as -o for output) to capture the current clipboard contents.
5. Captured data is stored temporarily in a file or directly streamed to a remote socket.
6. The exfiltrated data is transmitted to an attacker-controlled command-and-control server.
7. Attacker uses the stolen credentials or identifiers to move laterally or escalate privileges within the target network.

## Impact

The unauthorized collection of clipboard data can lead to the exfiltration of high-value credentials, secrets, and system configuration details. In enterprise environments, this intelligence allows attackers to pivot deeper into the network, compromise internal services, or facilitate further data exfiltration. The impact varies by the sensitivity of the data handled by the affected users, ranging from individual account compromise to broad administrative access loss.

## Recommendation

1. Deploy the provided Sigma rule to monitor for suspicious 'xclip' command executions in your SIEM.
2. Ingest Sysmon for Linux Event ID 1 (process creation) logs into your security platform to provide the required process name and command-line telemetry.
3. Normalize process execution telemetry using the Splunk Common Information Model (CIM) to ensure 'xclip' execution can be reliably searched across all Linux hosts.
4. Filter out known administrative or desktop automation scripts that legitimately use 'xclip' to reduce noise in the Security Operations Center.
