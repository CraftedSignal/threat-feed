---
title: Linux Persistence via System V Init Script Manipulation
slug: 2026-09-linux-init-d-persistence
description: Adversaries gain persistence on Linux systems by creating or modifying initialization scripts in /etc/init.d/ or /etc/init/, allowing for malicious code execution with root privileges during system boot.
date: "2026-09-11T12:50:06Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - linux
  - init-scripts
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries may add or alter files located in the /etc/init.d/ directory to execute malicious code upon boot in order to gain persistence on the system.
    confidence_band: high
rules:
  - title: Detect Unauthorized File Creation in Init Directories
    description: Detects file creation in Linux system initialization directories, which may indicate an attempt to gain persistence.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1543.002
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
    - action: Deploy the provided detection rule and baseline known package managers.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific paths and filter criteria for init persistence.
  hunt_leads:
    - lead: Audit /etc/init.d/ and /etc/init/ for files with recent modification timestamps.
      technique_id: T1543.002
      data_needed:
        - File metadata (ctime, mtime)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source highlights investigating files in init directories as a key triage step.
---

Adversaries targeting Linux systems frequently leverage legacy initialization directories to establish persistence. By placing malicious scripts or binaries within the /etc/init.d/, /etc/init/, or /etc/inittab directories, attackers ensure their code executes during the system startup process. Although modern Linux distributions have largely transitioned to systemd, the systemd-sysv-generator utility remains active on many systems to maintain backward compatibility, automatically converting these legacy files into functional systemd services.

When these scripts are processed, they typically execute with root-level privileges, providing the adversary with a highly privileged foothold. This technique is frequently observed in malware such as HiddenWasp, which utilizes these mechanisms to ensure survival across reboots. Detecting this behavior requires visibility into file creation and modification events within sensitive system directories, filtered against legitimate package management activity that may perform similar operations during software updates or system maintenance.

## Attack Chain

1. Attacker gains initial access to a Linux system (e.g., via exploit, credential theft, or web shell).
2. Attacker escalates privileges to root to gain write access to system directories.
3. Attacker crafts a malicious shell script or binary containing the desired payload.
4. Attacker writes the file to /etc/init.d/ or /etc/init/ to register it as a startup service.
5. Attacker marks the file as executable using the chmod utility.
6. The systemd-sysv-generator utility detects the new file and converts it into a systemd service unit.
7. Upon the next system reboot, the initialization process triggers the script, executing the malicious payload with root privileges.

## Impact

Successful exploitation allows attackers to maintain long-term persistence on compromised Linux servers, enabling data exfiltration, lateral movement, and command-and-control communication. Because the scripts run as root, this persistence mechanism is exceptionally difficult to remove without full incident response intervention. This technique affects any Linux environment where legacy System V initialization compatibility is maintained, particularly legacy infrastructure or servers configured to support older service management workflows.

## Recommendation

1. Deploy the Sigma rule provided below to monitor for suspicious file creation in initialization directories.
2. Baseline authorized software installation paths and package manager binaries (e.g., apt, dnf, rpm) to reduce false positives in the detection rule.
3. Regularly audit the /etc/init.d/ and /etc/init/ directories for unauthorized or unrecognized scripts.
4. Utilize the Osquery queries provided in the source metadata to perform routine integrity checks on these directories.
5. If an unauthorized script is discovered, isolate the host and perform a full forensic analysis to identify the initial compromise vector and hidden backdoors.
