---
title: Detection of Sensitive Data Aggregation via Compression Utilities
slug: 2026-08-sensitive-files-compression
description: Adversaries frequently use standard compression utilities like tar, zip, or gzip to aggregate sensitive files such as SSH keys, cloud credentials, and configuration files prior to exfiltration.
date: "2026-08-28T21:06:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - collection
  - linux
  - endpoint
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The detection rule identifies suspicious compression activities by monitoring process executions involving these utilities and targeting known sensitive file paths.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
    evidence: Identifies the use of a compression utility to collect known files containing sensitive information.
    confidence_band: high
references:
  - https://www.trendmicro.com/en_ca/research/20/l/teamtnt-now-deploying-ddos-capable-irc-bot-tntbotinger.html
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/credential_access_collection_sensitive_files.toml
rules:
  - title: Detect Sensitive Files Compression
    description: Detects the use of compression utilities to collect known files containing sensitive information, such as credentials and system configurations.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1005
      - T1552.001
      - T1560.001
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
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for detecting compression of sensitive paths
  hunt_leads:
    - lead: Search historical logs for execution of compression binaries with paths matching sensitive credentials
      technique_id: T1560.001
      data_needed:
        - process_creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule targets high-value paths commonly used by attackers
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict permissions on /etc/shadow and .ssh directories
      owner: IT Operations
      addresses: T1552.001
      evidence: Sensitive files are the target of the collection TTP
---

Adversaries targeting Linux environments often leverage native compression and archiving utilities to facilitate the collection and exfiltration of sensitive information. By executing tools such as tar, zip, gzip, or 7z against high-value file paths, attackers can bundle multiple sensitive assets into a single archive, minimizing the number of operations required for data theft and potentially avoiding certain network-based alerts by creating a single, contiguous stream of data. 

This activity typically targets files containing credentials, configuration data, and system identity information, including SSH keys (/root/.ssh/id_rsa), cloud provider credentials (/root/.aws/credentials), and sensitive system files (/etc/shadow). The use of these utilities for these specific paths, especially when initiated by non-administrative user accounts or outside of standard maintenance windows, is a strong indicator of unauthorized data collection and credential harvesting. Defenders should monitor for process executions of common compression utilities where the command-line arguments explicitly reference these sensitive file locations.

## Attack Chain

1. Attacker gains initial access or escalates privileges to the target Linux host.
2. Attacker performs local reconnaissance to identify stored credentials, configuration files, or identity data.
3. Attacker identifies high-value targets such as /etc/shadow, ~/.ssh/authorized_keys, or cloud configuration files.
4. Attacker executes a compression utility (e.g., tar -czf backup.tar.gz /home/user/.ssh/).
5. Attacker archives the collected sensitive files into a single compressed file within a temporary directory.
6. Attacker moves the archive to a staging location or prepares for immediate exfiltration.
7. Attacker exfiltrates the compressed archive via protocols like SCP, HTTP, or DNS tunneling.

## Impact

Successful exploitation allows an adversary to obtain plaintext credentials, SSH private keys, and cloud access tokens. This level of access typically leads to lateral movement within the environment, persistent access to cloud infrastructure, and full compromise of the target system. In enterprise environments, the exposure of such credentials can facilitate a broad range of malicious activities, including ransomware deployment or long-term persistence in the victim network.

## Recommendation

- Deploy the provided Sigma rule to monitor for suspicious process execution targeting sensitive paths.
- Implement process-level monitoring on all Linux endpoints using Auditbeat or Elastic Defend to capture command-line arguments for compression utilities.
- Review and establish an allowlist for known administrative backup jobs to reduce false positives triggered by legitimate maintenance tasks.
- Monitor for unusual outbound network traffic from sensitive hosts following the execution of archiving commands.
- Rotate credentials stored in files identified as frequently targeted by attackers if unauthorized access is suspected.
