---
title: Abuse of Curl for Linux Ingress Tool Transfer
slug: 2026-10-linux-curl-ingress
description: Detection of malicious actors using the curl utility on Linux systems to download remote scripts or binaries via common command-line flags.
date: "2026-10-12T17:50:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - ingress-tool-transfer
  - command-and-control
  - living-off-the-land
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The detection identifies the abuse of the 'curl' utility on Linux systems to perform ingress tool transfers.
    confidence_band: high
references:
  - https://gtfobins.github.io/gtfobins/curl/
  - https://curl.se/docs/manpage.html#-I
rules:
  - title: Detect Linux Ingress Tool Transfer via Curl
    description: Detects the use of the curl command with specific flags (-O, -sO, -ksO, --output) to download remote files, a common technique for ingress tool transfer.
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
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic requirement.
  hunt_leads:
    - lead: Search for curl processes with -O, -sO, or --output flags in historical logs.
      technique_id: T1105
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: TTP frequency in Linux-based attacks.
---

This threat brief focuses on the common TTP of utilizing the legitimate curl utility on Linux environments to facilitate Ingress Tool Transfer. Attackers frequently abuse curl to bypass simple security controls by fetching malicious payloads, stagers, or secondary toolsets from remote adversary-controlled infrastructure. This activity is a hallmark of initial access, post-compromise staging, and automated malware delivery, such as XorDDos or supply chain compromises. Defenders should monitor for curl executions that utilize output-writing flags, as these are atypical for standard administrative tasks when occurring in transient or non-standard directories. Monitoring these events allows for the identification of potential stage-two payloads before they are executed.

## Attack Chain

1. Attacker gains limited access to a Linux endpoint.
2. Attacker identifies a need to deploy additional malware or lateral movement tools.
3. Attacker uses the curl command-line utility to connect to an external server.
4. Attacker includes specific flags such as -O or --output to write the remote file to the local disk.
5. The file is saved into a writable directory, such as /tmp or /var/tmp.
6. Attacker grants execution permissions to the downloaded file using chmod.
7. Attacker executes the binary or script to further compromise the environment or establish C2.

## Impact

Successful abuse of curl for tool transfer enables attackers to drop payloads, establish persistent access, and expand their foothold within a Linux environment. This technique has been observed in various campaigns, including XorDDos infections and supply chain compromises. Unauthorized file transfers to local systems often serve as the bridge between initial access and full system control.

## Recommendation

* Deploy the Sigma rule provided in this brief to detect suspicious curl command-line arguments.
* Baseline legitimate automated scripts that use curl to identify and suppress high-volume false positives.
* Ensure Sysmon for Linux (Event ID 1) is deployed across all Linux assets to capture process name and command-line arguments.
* Hunt for processes spawning from /tmp, /var/tmp, or /dev/shm that correlate with prior curl file-transfer activity.
