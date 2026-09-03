---
title: Suspicious PowerShell Download and Execution Patterns
slug: 2026-09-powershell-download-patterns
description: Adversaries frequently leverage specific PowerShell cmdlets to download and execute malicious payloads, a common technique observed in stagers and ransomware deployment campaigns.
date: "2026-09-03T12:41:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - powershell
  - execution
  - stager
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml
  - https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70
  - https://www.trendmicro.com/en_us/research/22/j/lv-ransomware-exploits-proxyshell-in-attack.html
rules:
  - title: Detect Suspicious PowerShell Download and Execute Pattern
    description: Detects common PowerShell command patterns used to download and execute remote payloads via Net.WebClient
    platform: sigma
    severity: high
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for PowerShell download patterns.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided Sigma rule content.
  hunt_leads:
    - lead: Search for instances of Net.WebClient in PowerShell command lines within the last 30 days.
      technique_id: T1059.001
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known malicious stager behavior.
---

Security research and incident response data from various campaigns, including LV ransomware operations, identify a consistent pattern of abuse involving PowerShell's System.Net.WebClient class. Attackers use these cmdlets to fetch remote scripts or binaries directly into memory or the local filesystem for execution. By leveraging commands like DownloadString or DownloadFile, malicious actors bypass traditional file-based detection mechanisms. This behavior is commonly observed in the initial stager phases of an attack, where a small script is used to bootstrap more complex malware or C2 agents. Defenders should focus on process-creation logging to identify these specific command-line strings, as they are rarely used by legitimate business-critical applications.

## Impact

Successful execution of these commands leads to the unauthorized retrieval of malicious code or secondary payloads, often resulting in complete system compromise, credential theft, or the deployment of ransomware. These patterns have been historically associated with exploitation of vulnerabilities in public-facing services like Microsoft Exchange (e.g., ProxyShell) and subsequent lateral movement or impact.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for PowerShell command lines matching the suspicious download and execution patterns. Ensure your logging backend processes these strings as case-insensitive to avoid evasion via mixed-case variations.

- Enable Sysmon or Windows Event ID 4688 to capture the command-line arguments of all spawned PowerShell processes.
- Implement an allowlist for known, legitimate software installers or management scripts that utilize remote downloads to reduce false positives.
- Prioritize alerts for these command patterns when originating from web servers or public-facing applications.
