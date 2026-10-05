---
title: Detection of OpenSSH Backdoor Activity on Linux
slug: 2026-10-openssh-backdoor-detection
description: This detection logic identifies adversaries attempting to maintain persistence or harvest credentials by modifying OpenSSH binaries or configuration files, resulting in suspicious file creation events.
date: "2026-10-05T11:58:19Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - credential-access
  - linux
  - openssh
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Adversaries may modify SSH related binaries for persistence or credential access via patching sensitive functions to enable unauthorized access or to log SSH credentials for exfiltration.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1554
    technique_name: Compromise Host Software Binary
    evidence: Adversaries may modify SSH related binaries for persistence.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
    evidence: The rule monitors for suspicious file creation events... indicative of backdoor activity... staged data or inject malicious libraries.
    confidence_band: high
references:
  - https://github.com/eset/malware-ioc/tree/master/sshdoor
  - https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf
rules:
  - title: Potential OpenSSH Backdoor Logging Activity
    description: Identifies suspicious file creation by ssh or sshd processes, which may indicate backdoor persistence or credential staging.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1554
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for file creation by ssh/sshd.
      owner: Detection Engineering
      due: 48h
      evidence: Rule identification of persistence techniques.
  mitigation_plan:
    - priority: immediate
      action: Review SSH binary integrity via cryptographic checksums.
      owner: IT Operations
      addresses: T1554
      evidence: Source advice on binary integrity checks.
---

Adversaries frequently target OpenSSH to facilitate persistence or credential theft by patching sensitive functions within ssh or sshd binaries. This activity often involves modifying binary integrity or injecting malicious code that logs authentication credentials to localized files. The behavior manifests through the creation of files with unusual extensions, hidden naming conventions (e.g., dot-files), or staging activity within sensitive directories like /tmp, /var/tmp, or system library paths. Defenders should monitor for suspicious file creation events originating from ssh-related processes, as these often indicate the presence of a backdoor or an attempt to exfiltrate cached session data.

## Attack Chain

1. Attacker gains initial access to the Linux host via an unrelated vulnerability.
2. Attacker escalates privileges to root to gain write access to system binaries.
3. Attacker modifies the OpenSSH binary (sshd) or injects a shared object library to hook authentication functions.
4. Attacker creates hidden or masqueraded log files (e.g., .sshd_auth) to stage captured credentials.
5. Attacker stores temporary session data or malicious configuration files in world-writable directories such as /tmp or /var/tmp.
6. Attacker leverages the modified OpenSSH binary to persist in the environment and capture incoming user credentials.

## Impact

Successful exploitation allows for long-term persistence within the targeted Linux environment, unauthorized remote access, and the potential harvesting of user credentials as they authenticate via the SSH protocol. This creates a significant risk of lateral movement and full system compromise if credentials for administrative accounts are intercepted.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious file creation events associated with OpenSSH processes. Perform baseline integrity checks on ssh and sshd binaries using file hash comparisons. Investigate any alerts by verifying the associated user context and inspecting the contents of files created in sensitive directories like /tmp or /dev/shm. Ensure that automated configuration management tools like Ansible are excluded from these detection rules to minimize false positive noise.
