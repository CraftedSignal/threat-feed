---
brief_id: brief-2024-01-02-velociraptor-shell-execution
event_id: brief-2024-01-02-velociraptor-shell-execution
revision: 2
activity_at: "2026-11-20T03:11:01Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:921c91917243baa5a764c1b224aa7003859161b7eec1880d39ab65f244d4559d
    summary: exploited:true; KEV CVE-2025-26399
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Suspicious Shell Execution via Velociraptor
slug: 2024-01-velociraptor-shell-execution
description: Attackers are abusing the Velociraptor endpoint visibility and response tool to execute shell commands (cmd, PowerShell, rundll32) on compromised Windows systems, blending in with legitimate system processes.
date: "2024-01-02T12:00:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-03-09T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*
  - cpe:2.3:a:solarwinds:web_help_desk:12.8.7:-:*:*:*:*:*:*
tags:
  - velociraptor
  - command-and-control
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.001
    subtechnique_name: PowerShell
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
cves:
  - id: CVE-2025-26399
    cvss: 9.8
    epss: 0.895
    kev: true
    kev_status: "true"
references:
  - https://www.huntress.com/blog/active-exploitation-solarwinds-web-help-desk-cve-2025-26399
  - https://attack.mitre.org/techniques/T1219/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_rmm_software_installation_from_commonly_abused_web_service.toml
rules:
  - title: Suspicious Shell Execution via Velociraptor
    description: Detects shell executions (cmd, PowerShell, rundll32) spawned by Velociraptor.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Velociraptor Executing Cmd with Suspicious Arguments
    description: Detects Velociraptor spawning cmd.exe with command line arguments indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.003
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-09-14T12:54:27Z"
    level: L2
    summary: added CVE-2025-26399;
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_rmm_software_installation_from_commonly_abused_web_service.toml
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-26399
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Velociraptor is a legitimate open-source endpoint visibility and response tool. Threat actors are abusing Velociraptor by installing it on compromised Windows systems and using it to execute shell commands (cmd, PowerShell, rundll32), effectively hiding their malicious activity within normal system processes. This allows attackers to perform various actions on the compromised host, such as data exfiltration, lateral movement, and credential access, while evading traditional detection methods. The activity was observed in relation to exploitation of CVE-2025-26399, a vulnerability in SolarWinds Web Help Desk. Defenders need to differentiate between legitimate and malicious use of Velociraptor to prevent further compromise.

## Attack Chain

1. Initial access is gained through exploitation of a vulnerability (e.g., CVE-2025-26399 in SolarWinds Web Help Desk).
2. Velociraptor is installed on the compromised Windows host, potentially using a script or other automated method.
3. The attacker configures Velociraptor with malicious artifacts or uses it to execute arbitrary commands.
4. Velociraptor spawns a shell process (cmd.exe, powershell.exe, or rundll32.exe) to execute the attacker's commands.
5. The shell process executes malicious commands, such as downloading additional tools, performing reconnaissance, or exfiltrating data.
6. The attacker uses the shell to perform lateral movement to other systems within the network.
7. The attacker escalates privileges using further commands executed via Velociraptor's spawned shells.
8. The final objective is achieved, such as data theft, system disruption, or ransomware deployment.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on compromised Windows systems, leading to data theft, system compromise, and potential lateral movement within the network. The use of Velociraptor makes detection challenging, as the activity blends in with legitimate system administration tasks. The scope of impact depends on the level of access gained and the attacker's objectives. While specific victim numbers are unknown, observed use alongside CVE-2025-26399 suggests widespread potential.

## Recommendation

*   Enable Sysmon process creation logging to capture the execution of shell processes and their command lines, allowing for detection of malicious activity (Data Source: Sysmon).
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious shell executions spawned by Velociraptor, and tune for your specific environment.
*   Investigate any instances of Velociraptor installations from unusual paths (e.g., temp directories) to identify potentially unauthorized deployments (see Overview).
*   Monitor network connections originating from Velociraptor processes for suspicious destinations or unusual protocols, indicating potential data exfiltration or C2 communication.
*   Patch CVE-2025-26399 on affected SolarWinds Web Help Desk instances (see References).
