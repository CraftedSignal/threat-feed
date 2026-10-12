---
title: BITS Job Persistence via Bitsadmin
slug: 2026-10-bits-job-persistence
description: Adversaries leverage the Windows Background Intelligent Transfer Service (BITS) utility bitsadmin.exe to establish persistence, download malicious payloads, or exfiltrate data by creating and scheduling jobs.
date: "2026-10-12T17:36:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - living-off-the-land
  - windows
  - bitsadmin
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: The following analytic detects the use of bitsadmin.exe to schedule a BITS job for persistence on an endpoint.
    confidence_band: high
rules:
  - title: Detect BITS Job Persistence via Bitsadmin
    description: Detects the use of bitsadmin.exe to create, add files to, or resume BITS jobs which may indicate persistence or malicious file transfer
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM and monitor for bitsadmin.exe usage patterns
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation for T1197 persistence techniques
  hunt_leads:
    - lead: Search historical logs for bitsadmin.exe execution patterns involving persistence-related arguments
      technique_id: T1197
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The utility is a common vector for living-off-the-land persistence
---

The Background Intelligent Transfer Service (BITS) is a Windows service designed to facilitate file transfers between machines using idle network bandwidth. Threat actors frequently exploit the `bitsadmin.exe` command-line utility to repurpose this service for malicious objectives. By creating, configuring, and resuming BITS jobs, attackers can achieve persistent execution of arbitrary code, orchestrate the download of second-stage malware, or facilitate the exfiltration of sensitive information. Because BITS activity is a standard component of Windows operations, this technique provides a high degree of stealth, allowing malicious jobs to blend in with legitimate system tasks. Defenders should focus on monitoring for the execution of `bitsadmin.exe` with specific flags associated with job management and persistence.

## Impact

Successful exploitation allows an adversary to maintain long-term access to compromised endpoints, execute arbitrary commands via scheduled BITS notifications, and perform stealthy data exfiltration. This technique is observed across a wide range of Windows environments and is frequently used in multi-stage attack campaigns targeting both corporate and governmental sectors.

## Recommendation

Prioritize the implementation of process-creation logging to monitor for suspicious `bitsadmin.exe` execution.

* Deploy the Sigma rule below to detect suspicious BITS job creation parameters.
* Enable Sysmon Event ID 1 or Windows Security Event ID 4688 to capture the full command-line arguments, including the process name, parent process, and command-line parameters.
* Tune detections by establishing an allowlist based on legitimate software that utilizes `bitsadmin.exe` in the specific environment.
