---
title: Detection of Unauthorized SSH Binary and Library Modification
slug: 2026-10-linux-ssh-binary-modification
description: Adversaries modify critical SSH binaries and libraries on Linux systems to establish persistence, gain unauthorized access, or harvest credentials through patched sensitive functions.
date: "2026-10-05T11:59:54Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - credential-access
  - linux
  - ssh
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1554
    technique_name: Compromise Host Software Binary
    evidence: Adversaries may modify SSH related binaries for persistence or credential access by patching sensitive functions.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1554
    technique_name: Compromise Host Software Binary
    evidence: patching sensitive functions to enable unauthorized access or by logging SSH credentials for exfiltration.
    confidence_band: high
references:
  - https://blog.angelalonso.es/2016/09/anatomy-of-real-linux-intrusion-part-ii.html
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_credential_access_modify_ssh_binaries.toml
rules:
  - title: Detect Unauthorized Modification of OpenSSH Binaries
    description: Detects unauthorized modifications to OpenSSH binaries and critical libraries that may indicate persistence or credential theft attempts.
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
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor critical SSH file integrity
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific paths and processes for detection
  mitigation_plan:
    - priority: medium_term
      action: Enable integrity monitoring and restrict write access to /usr/bin and /usr/sbin directories to root-only and service-account-restricted processes
      owner: IT Operations
      addresses: T1554
      evidence: Best practice for protecting system binaries
---

Adversaries targeting Linux environments may attempt to compromise the integrity of the OpenSSH suite to maintain long-term access or facilitate credential theft. By modifying binaries such as /usr/bin/ssh, /usr/bin/scp, /usr/bin/sftp, /usr/sbin/sshd, or linked libraries like libkeyutils.so, attackers can patch internal functions. These modifications enable malicious actors to capture cleartext credentials during authentication or create backdoors that bypass standard access controls. This activity typically occurs post-exploitation when an attacker has achieved sufficient privileges to modify system-level files. Monitoring for unauthorized changes to these specific sensitive paths is critical for identifying potential subversion of the operating system's primary secure communication mechanism. Defenders must distinguish these malicious modifications from legitimate software updates and administrative maintenance activities.

## Impact

Successful modification of SSH binaries results in a complete compromise of the affected host's secure remote access. Attackers gain the ability to exfiltrate valid user credentials as they are entered, effectively turning the SSH server into a credential harvesting tool. This often leads to lateral movement within the network as compromised accounts are reused across other systems. If not detected, such persistence mechanisms can remain active indefinitely, allowing attackers to maintain access even if primary entry points are remediated.

## Recommendation

- Implement File Integrity Monitoring (FIM) or use EDR solutions to monitor modification events on critical binaries: /usr/bin/scp, /usr/bin/sftp, /usr/bin/ssh, /usr/sbin/sshd, and libkeyutils.so.
- Deploy the Sigma rules below to your SIEM to alert on unauthorized file changes.
- Establish an allowlist for known-good update processes (e.g., dnf, apt, yum, packagekitd) to minimize false positives during system maintenance.
- Investigate any process modifying these binaries that does not originate from a recognized package manager or administrative update task.
- Regularly audit system binaries for signature mismatches or unexpected file size variations.
