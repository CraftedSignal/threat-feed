---
title: SSH Authorized Key File Activity Detected in Containers
slug: 2026-07-ssh-authorized-keys-container
description: Adversaries may modify the Secure Shell (SSH) authorized_keys file inside Linux containers to maintain persistence, achieve lateral movement, or escalate privileges by adding their own public keys, with this activity detected by Elastic Defend for Containers.
date: "2026-07-29T13:02:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - linux
  - persistence
  - lateral-movement
  - privilege-escalation
  - ssh
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s).
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Unexpected and unauthorized SSH usage inside a container can be an indicator of compromise and should be investigated.
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1563
    technique_name: Remote Service Session Hijacking
    evidence: By monitoring file modifications, it helps detect unauthorized SSH usage, a common indicator of compromise.
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s).
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/persistence_ssh_authorized_keys_modification_inside_a_container.toml
rules:
  - title: Detect SSH Authorized Key File Activity in Linux Containers
    description: Detects the creation or modification of the `authorized_keys` or `authorized_keys2` file inside a Linux container, which adversaries may modify to maintain persistence on a victim host by adding their own public key(s). This indicates potential unauthorized SSH access, lateral movement, or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - persistence
      - privilege_escalation
    techniques:
      - T1021.004
      - T1098.004
      - T1563.001
    data_sources:
      - file_event
      - linux
rules_count: 1
---

Adversaries frequently seek to establish persistence and expand their access within compromised environments. A common technique for this in Linux systems is the modification of the SSH `authorized_keys` file. This file, typically located in a user's home directory under `.ssh/`, allows public key authentication for SSH access. By adding their own public keys to this file, attackers can ensure continued unauthorized access to a system, even if other credentials are changed. This threat brief focuses on the detection of such modifications specifically within containerized environments, leveraging Elastic Defend for Containers. The detection of unexpected changes or creations of `authorized_keys` files inside a container is a critical indicator of potential compromise, suggesting an adversary is attempting to establish a backdoor for ongoing control, pivot to other containers, or elevate privileges within the compromised host.

## Impact

Successful modification of an SSH `authorized_keys` file by an adversary inside a container grants them persistent, unauthorized remote access to that container, potentially as a privileged user. This can lead to further lateral movement within the containerized environment, compromise of sensitive data, execution of malicious payloads, and disruption of services. While no specific victim count or sectors are provided in the source, any organization leveraging Linux containers is susceptible. The primary impact is continued unauthorized access and the potential for a broader compromise of the host system or other services within the network.

## Recommendation

* Deploy the Sigma rule "Detect SSH Authorized Key File Activity in Linux Containers" to your SIEM and tune it for your environment to identify suspicious `authorized_keys` file modifications or creations within containers.
* Configure Elastic Defend for Containers or equivalent log sources to collect `file_event` data from all Linux containers to ensure the detection rule has the necessary telemetry.
* Upon detection, immediately review the `container.id` and `event.type` associated with the alert to pinpoint the specific container and action that occurred.
* Investigate the user account and process responsible for the `authorized_keys` modification and analyze the file's contents for unauthorized keys, as described in the investigation guide.
* Isolate affected containers to prevent further unauthorized access or lateral movement as part of your incident response plan.
* Conduct thorough review of container logs and network activity for signs of compromise, and potentially restore compromised containers from a known good backup.
