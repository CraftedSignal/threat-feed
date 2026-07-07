---
title: Potential Unquoted Service Path Reconnaissance Via Wmic.EXE
slug: 2026-07-wmic-unquoted-service-recon
description: Attackers and pentesters commonly use `wmic.exe` to query Windows service configurations for unquoted paths, a reconnaissance technique that identifies potential privilege escalation opportunities.
date: "2026-07-03T14:53:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - privilege-escalation
  - windows
  - wmic
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: Detects known WMI recon method to look for unquoted service paths using wmic.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: looking for unquoted service paths using wmic... service get name,displayname,pathname,startmode
    confidence_band: high
cves:
  - id: CVE-2017-1014
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_recon_unquoted_service_search.yml
  - https://github.com/nccgroup/redsnarf/blob/35949b30106ae543dc6f2bc3f1be10c6d9a8d40e/redsnarf.py
  - https://github.com/S3cur3Th1sSh1t/Creds/blob/eac23d67f7f90c7fc8e3130587d86158c22aa398/PowershellScripts/jaws-enum.ps1
  - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
rules:
  - title: Potential Unquoted Service Path Reconnaissance Via Wmic.EXE
    description: Detects attacker enumeration for unquoted service paths using wmic.exe, a common reconnaissance step for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1047
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Attackers and penetration testers frequently employ `wmic.exe` as a reconnaissance tool to identify Windows services configured with unquoted executable paths. This technique involves querying service properties like `name`, `displayname`, `pathname`, and `startmode` using specific `wmic` commands. The absence of quotes around executable paths in service configurations is a well-known vulnerability (CVE-2017-1014) that can lead to privilege escalation. By dropping a malicious executable in a specific directory within an unquoted path, an attacker can trick the system into executing their code with elevated privileges when the legitimate service starts. This detection focuses on the enumeration phase, allowing defenders to identify attempts to discover these weak configurations before exploitation occurs. Early detection of such reconnaissance is crucial as it indicates an attacker actively seeking to escalate privileges on a compromised system.

## Impact

Successful exploitation of an unquoted service path vulnerability, after such reconnaissance, can lead to privilege escalation, allowing an attacker to execute arbitrary code with SYSTEM privileges. This level of access grants full control over the compromised system, enabling further lateral movement, data exfiltration, or the deployment of additional malicious payloads such as ransomware. Organizations that rely on Windows services for critical operations are particularly vulnerable, as compromise of these services can lead to severe operational disruption and data loss.

## Recommendation

*   Deploy the Sigma rule "Potential Unquoted Service Path Reconnaissance Via Wmic.EXE" to your SIEM solution to detect attacker enumeration for privilege escalation.
*   Ensure process creation logging, especially for `wmic.exe`, is enabled and properly configured on all Windows endpoints to provide the necessary telemetry for this rule.
*   Regularly audit Windows service configurations for unquoted paths and remediate them by ensuring all service executable paths are properly enclosed in double quotes.
