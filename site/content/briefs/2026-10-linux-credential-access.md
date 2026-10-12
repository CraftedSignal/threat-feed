---
title: Detection of Unauthorized Access to Linux Credential Files
slug: 2026-10-linux-credential-access
description: This detection targets adversary efforts to perform credential dumping on Linux systems by monitoring for the usage of standard utilities to access /etc/passwd and /etc/shadow files.
date: "2026-10-12T17:49:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - persistence
  - privilege-escalation
  - linux
  - auditd
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The following analytic detects attempts to access or dump the contents of /etc/passwd and /etc/shadow files on Linux systems.
    confidence_band: high
rules:
  - title: Detect Access to Linux Credential Files
    description: Detects the use of common utilities like cat, nano, or vim to access /etc/passwd or /etc/shadow, which may indicate credential dumping attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.008
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect credential file access.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided by source content.
  hunt_leads:
    - lead: Search historical logs for usage of cat/vim on /etc/shadow.
      technique_id: T1003.008
      data_needed:
        - Auditd proctitle logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries frequently use standard utilities for credential dumping.
  mitigation_plan:
    - priority: short_term
      action: Restrict access to /etc/shadow to root-only and audit all access attempts.
      owner: IT Operations
      addresses: T1003.008
      evidence: General security best practices for Linux credential protection.
---

Adversaries targeting Linux environments frequently attempt to retrieve sensitive credential information to enable lateral movement, persistence, or privilege escalation. A primary method for achieving this is the extraction of user account details and password hashes from system files located at /etc/passwd and /etc/shadow. This detection identifies anomalous activity where standard command-line utilities and text editors, specifically 'cat', 'nano', 'vim', and 'vi', are utilized to read these sensitive files. This behavior is a strong indicator of post-compromise activity, as legitimate system administration tasks involving these specific tools and file paths are often scripted or restricted to specialized security maintenance windows. Detection engineers should correlate this activity with other anomalous signals, such as unexpected remote access or suspicious lateral movement attempts, to validate malicious intent.

## Attack Chain

1. Attacker gains initial access to the Linux endpoint via exploitation or stolen credentials.
2. Attacker performs local reconnaissance to identify target files in /etc/.
3. Attacker uses native binaries like 'cat' or editors like 'vim'/'vi' to interact with /etc/passwd or /etc/shadow.
4. System auditd logs the process execution and the associated command-line arguments.
5. Security platform ingests the auditd proctitle event.
6. Detection logic triggers based on the matching process name and sensitive target file.
7. Adversary exfiltrates the contents of these files to an external command-and-control server.
8. Adversary performs offline password cracking to escalate privileges to root or pivot to other systems.

## Impact

Successful unauthorized access to /etc/passwd and /etc/shadow allows adversaries to obtain user account information and hashed passwords. Offline cracking of these hashes can lead to full system compromise, escalation to root-level privileges, and facilitate lateral movement throughout the target network. This technique is observed across multiple adversary groups and is a fundamental component of the post-compromise phase in Linux-based cyberattacks.

## Recommendation

- Deploy the Sigma rule provided in this brief to identify attempts to read sensitive credential files.
- Integrate Linux Auditd logs into the SIEM, specifically focusing on SYSCALL, TYPE, EXECVE, and PROCTITLE events.
- Implement process-level monitoring for unauthorized access to /etc/passwd and /etc/shadow, and tune the detection based on known administrative baselines.
- Use the provided drilldown searches in your SOC platform to review historical risk events associated with the affected destination host.
