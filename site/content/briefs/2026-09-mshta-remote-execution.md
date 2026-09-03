---
title: Remotely Hosted HTA Execution via Mshta.exe
slug: 2026-09-mshta-remote-execution
description: Adversaries utilize the legitimate Windows mshta.exe utility to execute remote malicious HTA files, bypassing security controls by fetching code directly from web-based infrastructure.
date: "2026-09-03T12:40:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - execution
  - windows
  - mshta
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Detects execution of the mshta utility with an argument containing the http keyword
    confidence_band: high
rules:
  - title: Detect Remotely Hosted HTA Execution via Mshta.exe
    description: Detects execution of the mshta utility with an argument containing web-based protocols, which indicates the execution of a remotely hosted malicious HTA file.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for mshta.exe with network-based arguments
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief
  hunt_leads:
    - lead: Search historical logs for mshta.exe command lines containing http, https, or ftp
      technique_id: T1218.005
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly flags this behavior as malicious
  mitigation_plan:
    - priority: medium_term
      action: Restrict mshta.exe network access via host-based firewall if not required for business operations
      owner: IT Operations
      addresses: T1218.005
      evidence: Source confirms abuse of network protocols via mshta
---

The Microsoft HTML Application host (mshta.exe) is a built-in Windows utility designed to execute .hta files. Threat actors frequently abuse this binary to execute arbitrary code by pointing it to a remotely hosted malicious file via HTTP, HTTPS, or FTP protocols. This technique allows attackers to load malicious payloads into memory, evading traditional file-based detection mechanisms. By executing scripts directly from a URL, the attacker minimizes the local file footprint, facilitating stealthy initial access or lateral movement. Defenders should monitor for mshta.exe command-line arguments that include remote URI schemes, as this behavior is rarely observed in standard administrative or user activity.

## Attack Chain

1. Attacker stages a malicious HTA file on an internet-facing web server or compromised infrastructure.
2. The victim is lured into interacting with a malicious link or a document containing a trigger command.
3. The trigger initiates the execution of 'mshta.exe' via command line, shell link, or another script.
4. 'mshta.exe' makes an outbound HTTP/HTTPS request to the attacker-controlled URI to fetch the HTA payload.
5. The HTA application engine parses the returned content, which contains embedded VBScript or JScript.
6. The script executes within the context of the mshta process, potentially spawning child processes like 'powershell.exe' or 'cmd.exe'.
7. The attacker achieves code execution to establish persistence, exfiltrate data, or deploy secondary malware.

## Impact

Successful exploitation leads to full code execution within the security context of the user, potentially resulting in complete system compromise, the deployment of ransomware, or long-term unauthorized access to the network.

## Recommendation

Deploy the provided Sigma detection rule to flag instances where mshta.exe is invoked with remote URI parameters. Configure EDR or logging solutions to monitor process creation events and block outbound network connections from mshta.exe to unknown or untrusted external domains.
