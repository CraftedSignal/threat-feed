---
title: Potential macOS Privacy Control Bypass via Localhost SCP
slug: 2026-10-macos-privacy-bypass
description: Adversaries can exploit the inclusion of sshd in the macOS Full Disk Access list by using localhost-targeted SCP commands to bypass privacy restrictions and access sensitive files.
date: "2026-10-07T16:39:46Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - macos
  - defense-evasion
  - privilege-escalation
  - collection
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Identifies use of the Secure Copy Protocol (SCP) to copy files locally by abusing the auto addition of the Secure Shell Daemon (sshd) to the authorized application list for Full Disk Access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries may misuse SCP to locally copy files, evading security measures.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This may indicate attempts to bypass macOS privacy controls to access sensitive files.
    confidence_band: high
references:
  - https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/xcsset-mac-malware--infects-xcode-projects--uses-0-days
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/defense_evasion_privilege_escalation_privacy_pref_sshd_fulldiskaccess.toml
rules:
  - title: Detect Potential Privacy Control Bypass via Localhost Secure Copy
    description: Detects the use of SCP to copy files locally by potentially abusing the sshd inclusion in the Full Disk Access list.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1005
      - T1548
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for localhost SCP activity
      owner: Detection Engineering
      due: 48h
      evidence: Rule definition in brief
  hunt_leads:
    - lead: Search endpoint logs for SCP processes with StrictHostKeyChecking disabled
      technique_id: T1548
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes localhost SCP abuse as an evasion technique
  mitigation_plan:
    - priority: medium_term
      action: Audit Full Disk Access permissions for sshd
      owner: IT Operations
      addresses: T1548
      evidence: Abuse of sshd FDA list is the core mechanism
---

Adversaries targeting macOS systems may exploit misconfigurations or legitimate administrative accessibility to circumvent system-level privacy protections. Specifically, if the Secure Shell Daemon (sshd) has been granted Full Disk Access (FDA), attackers can leverage it to access restricted files. By executing Secure Copy Protocol (SCP) commands targeting the localhost (127.0.0.1) and disabling host key verification, an attacker can trick the system into using the privileged sshd process to read files that the user-level process would otherwise be denied. This technique has been observed in the wild, notably by malware families like XCSSET, to facilitate the unauthorized collection of sensitive data. Defenders must monitor for suspicious SCP activity that deviates from standard administrative or development workflows, such as those performed by Vagrant or legitimate deployment scripts.

## Attack Chain

1. Attacker gains initial access to a user account on a macOS system.
2. Attacker confirms the presence of the SSH daemon in the macOS Full Disk Access list (System Settings > Privacy & Security > Full Disk Access).
3. Attacker identifies a target sensitive file located in a protected directory (e.g., ~/Library/Application Support/ or other restricted paths).
4. Attacker constructs an SCP command targeting localhost (scp -o StrictHostKeyChecking=no localhost:/path/to/sensitive/file /tmp/staging).
5. The SCP process initiates a connection to the local sshd, which leverages its FDA privileges to bypass standard file system access controls.
6. The sensitive file is copied to an attacker-controlled or accessible temporary directory.
7. Attacker exfiltrates the collected data from the system.

## Impact

Successful exploitation allows an unauthorized party to read arbitrary files on the macOS host, bypassing mandatory access controls enforced by the OS. This can lead to the exfiltration of credentials, browser data, configuration files, and other sensitive user information. While the specific number of victims varies, the technique is a known vector for macOS-targeting malware to achieve broader system access and persistent collection capabilities.

## Recommendation

Prioritize monitoring of SCP command lines on all managed macOS endpoints.
- Deploy the provided detection rule to identify local SCP usage with insecure host key checking flags.
- Audit the 'Full Disk Access' list on critical macOS systems to identify and remove unauthorized binaries, specifically ensuring sshd is not unnecessarily granted broad disk access.
- Implement endpoint monitoring via an EDR solution to alert on non-standard SCP behavior.
- Restrict access to sensitive system directories to prevent unauthorized user-level interaction.
