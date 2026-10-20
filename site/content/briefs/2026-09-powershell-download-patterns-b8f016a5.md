---
brief_id: brief-2026-09-powershell-download-patterns
event_id: brief-2026-09-powershell-download-patterns
revision: 2
activity_at: "2026-09-01T12:23:10Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:7a5e22354ce1f3d870e31aee64fc1d2181343255ad1514e7edebe2bd4c76cb87
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Detection of PowerShell Download Patterns
slug: 2026-09-powershell-download-patterns-b8f016a5
description: This brief details a detection strategy for identifying PowerShell command-line activity associated with common file download patterns used by various threat actors.
date: "2026-09-01T12:23:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "3"
  rating: A3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Test cases defined; needs environment validation.
tags:
  - detection-engineering
  - powershell
  - execution
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects a Powershell process that contains download commands in its command line string.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml
  - https://blog.redteam.pl/2020/06/black-kingdom-ransomware.html
  - https://lab52.io/blog/winter-vivern-all-summer/
  - https://hatching.io/blog/powershell-analysis/
rules:
  - title: Detect Suspicious PowerShell Download Patterns
    description: Detects a PowerShell process that contains download commands in its command line string using .NET WebClient class
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM and monitor for high-volume hits that may indicate legitimate internal tooling.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for historical process creation events containing 'net.webclient' in the command line over the past 30 days.
      technique_id: T1059.001
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This pattern is a frequent indicator of malicious PowerShell usage.
---

This detection focuses on identifying suspicious use of the .NET WebClient class within PowerShell to download files or strings from the internet. This technique is frequently utilized by threat actors during the initial access or post-exploitation phases to fetch secondary payloads, modular malware, or remote access trojans (RATs). While the use of PowerShell for legitimate administrative tasks is common, the specific combination of 'new-object', 'net.webclient', and 'download' methods within the command line is highly indicative of malicious activity. This detection is designed to capture standard PowerShell (powershell.exe), PowerShell ISE (powershell_ise.exe), and PowerShell Core (pwsh.exe).

## Impact

Successful exploitation of this technique allows attackers to download and execute arbitrary code on a compromised host. This can lead to full system compromise, exfiltration of sensitive information, or the deployment of ransomware. Attackers leverage these patterns to maintain stealth while bypassing standard file-based security controls by executing payloads directly into memory or saving them to temporary directories.

## Recommendation

Deploy the provided Sigma rule to your SIEM and tune it to baseline legitimate administrative scripts that may utilize .NET classes. Ensure that PowerShell script block logging (Event ID 4104) is enabled, as it provides higher visibility into obfuscated command lines that might bypass simple process-creation based detection.
