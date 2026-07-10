---
title: AMOS Stealer macOS VM Detection
slug: 2024-01-09-amos-stealer-vm-check
description: This brief describes detection of AMOS Stealer checking for virtual machine environments on macOS via osascript and system_profiler, potentially leading to information theft and further malicious activity.
date: "2024-01-09T16:25:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - AMOS Stealer
tags:
  - amos-stealer
  - hellcat-ransomware
  - macos
  - vm-detection
vendors:
  - Apple
products:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://osquery.readthedocs.io/en/stable/deployment/process-auditing/
  - https://www.virustotal.com/gui/search/behaviour_processes%253A%2522osascript%2520-e%2520set%2522%2520AND%2520behaviour_processes%253A%2522system_profiler%2522%2520AND%2520(behaviour_processes%253A%2522VMware%2522%2520OR%2520behaviour_processes%253A%2522QEMU%2522)?type=files
rules:
  - title: Detect AMOS Stealer VM Check Activity
    description: Detects AMOS Stealer's virtual machine check activity using osascript and system_profiler on macOS
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1059.002
      - T1082
    data_sources:
      - process_creation
      - macos
  - title: Detect AMOS Stealer system_profiler Usage
    description: Detects suspicious usage of system_profiler via shell
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

AMOS Stealer is a malware strain targeting macOS systems with the goal of stealing sensitive information. This malware employs various techniques to evade detection, including checking if the infected system is running within a virtual machine. This is likely done to hinder analysis and prevent execution in sandboxed environments. The observed behavior leverages `osascript` to execute AppleScript commands that utilize `system_profiler` to identify virtualized environments like VMware or QEMU. The activity is typically seen after initial infection, when the stealer probes the environment. Successful execution suggests the system is not a VM and is a viable target for data exfiltration and further malicious actions.

## Attack Chain

1.  Initial Access: User unknowingly downloads and executes a malicious application or script containing the AMOS Stealer payload.
2.  Persistence: AMOS Stealer establishes persistence on the macOS system, ensuring it runs automatically on startup (details of how this is achieved are not in the provided document).
3.  VM Check: The malware executes `osascript` with a crafted AppleScript command to run `system_profiler`.
4.  Environment Enumeration: `system_profiler` gathers system information, specifically looking for virtualization platforms (VMware, QEMU).
5.  Result Analysis: The output of `system_profiler` is analyzed to determine if the system is running in a VM.
6.  Data Theft: If the system is not a VM, AMOS Stealer proceeds to collect sensitive data such as browser credentials, crypto wallets, and other user data (specific paths and files are not in the source).
7.  C2 Communication: The stolen data is exfiltrated to a command-and-control server controlled by the attacker (specific details are not in the provided document).
8.  Potential Ransomware Deployment: In some cases, AMOS Stealer infections can lead to the deployment of ransomware such as Hellcat.

## Impact

A successful AMOS Stealer infection can lead to significant data loss, including sensitive credentials and financial information. If Hellcat ransomware is deployed, it can encrypt critical files, disrupting business operations and potentially resulting in financial losses. While specific victim counts and sectors are unavailable from the given source, macOS users are at risk, specifically those handling cryptocurrency or sensitive data.

## Recommendation

*   Enable Osquery and monitor process execution for `osascript` with command-line arguments containing `system_profiler`, `VMware`, and `QEMU` as covered in the overview, and described in the references.
*   Deploy the Sigma rule "Detect AMOS Stealer VM Check Activity" to your SIEM and tune for your environment to detect the specific `osascript` activity.
*   Investigate any endpoint triggering the "Detect AMOS Stealer VM Check Activity" rule, looking for associated persistence mechanisms or data exfiltration attempts.
*   Consider implementing application control to restrict the execution of unauthorized applications, reducing the risk of initial infection.
