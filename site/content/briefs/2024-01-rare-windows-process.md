---
title: Unusual Process For a Windows Host via Machine Learning
slug: 2024-01-rare-windows-process
description: This rule detects rare processes running on Windows hosts, potentially indicating unauthorized services, malware, or persistence mechanisms by using machine learning to identify processes that run infrequently compared to other processes on the same host.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
rules:
  - title: Detecting Rare Process Execution on Windows Host
    description: Detects rare process executions on Windows hosts using process creation logs, which may indicate malware or unauthorized activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detecting Unusual Service Creation
    description: Detects unusual service creation by monitoring registry modifications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This detection rule leverages machine learning to identify processes that are rarely executed on individual Windows hosts. The goal is to detect the execution of unauthorized services, malware, or persistence mechanisms. The rule focuses on processes that run occasionally compared to the baseline of other processes on the same host. This approach can help uncover suspicious behaviors that might be missed by traditional signature-based detections. It utilizes the 'v3_rare_process_by_host_windows' machine learning job and requires either Elastic Defend or Windows integration for data collection. The rule was last updated on 2026/02/27, indicating ongoing maintenance and relevance.

## Attack Chain

1.  **Initial Access (Likely):** An attacker gains initial access to a Windows host through various methods such as phishing, exploitation of vulnerabilities, or stolen credentials (not directly covered in the source but a common precursor).
2.  **Persistence:** The attacker attempts to establish persistence by installing a malicious service or scheduling a task to run a payload. This ensures continued access even after a reboot.
3.  **Execution:** The malicious service or scheduled task executes a rare or unusual process on the host. This could involve running a custom malware executable or leveraging a built-in Windows tool in an unexpected way.
4.  **Defense Evasion:** The attacker may attempt to evade detection by renaming the malicious executable or placing it in a seemingly legitimate directory.
5.  **Discovery:** The attacker may use the compromised host to gather information about the network, other systems, and user accounts.
6.  **Lateral Movement:** Using the gathered information, the attacker attempts to move laterally to other systems on the network.
7.  **Command and Control:** The rare process may establish a connection to a command and control (C2) server to receive instructions from the attacker.
8.  **Impact:** The attacker achieves their objectives, such as data exfiltration, ransomware deployment, or system disruption.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, system compromise, and potential disruption of business operations. The severity depends on the specific actions taken by the attacker after gaining a foothold on the system, ranging from data theft to complete system takeover. The number of victims and sectors targeted will vary depending on the attacker's objectives and the scope of the compromised environment.

## Recommendation

*   Enable either Elastic Defend or Windows integration to ensure proper data collection for the machine learning job (`machine_learning_job_id`).
*   Review and tune the `false_positives` list with user and command line conditions relevant to your environment.
*   Investigate the process execution chain of detected rare processes to identify the root cause of the unusual activity (reference the "Triage and analysis" section in the content).
*   Use Osquery to examine the DNS cache, host services, and unsigned executables (`transform.osquery`) to understand the context surrounding the rare process execution.
*   Implement response actions like isolating affected hosts and blocking indicators of compromise as described in the "Response and Remediation" section.
