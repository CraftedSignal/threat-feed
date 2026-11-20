---
brief_id: brief-2024-01-02-powershell-encoded-command
event_id: brief-2024-01-02-powershell-encoded-command
revision: 1
activity_at: "2024-01-02T12:00:00Z"
title: Malicious PowerShell Use of EncodedCommand Parameter
slug: 2024-01-02-powershell-encoded-command
description: Detection of PowerShell processes using the EncodedCommand parameter, often used by adversaries to obfuscate malicious scripts for unauthorized access, privilege escalation, or persistence.
date: "2024-01-02T12:00:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2022-08-18T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1909:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_20h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h1:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - powershell
  - encodedcommand
  - defense-evasion
vendors:
  - Microsoft
  - Rapid7
products:
  - Active Directory Certificate Services
  - Cortex Cloud Identity Security
  - Cortex XDR
  - Cortex XSIAM
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
cves:
  - id: CVE-2025-59287
    cvss: 9.8
    epss: 0.71403
    kev: true
    kev_status: "true"
  - id: CVE-2022-26923
    cvss: 8.8
    epss: 0.91441
    kev: true
    kev_status: "true"
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/malicious_powershell_process___encoded_command.yml
  - https://regexr.com/662ov
  - https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/Windows/TestHarnesses/T1059.001_PowerShell/OutPowerShellCommandLineParameter.ps1
  - https://ss64.com/ps/powershell.html
  - https://twitter.com/M_haggis/status/1440758396534214658?s=20
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
  - https://unit42.paloaltonetworks.com/active-directory-certificate-services-exploitation/
rules:
  - title: Detect PowerShell Encoded Command
    description: Detects PowerShell processes using the EncodedCommand parameter to execute Base64-encoded commands, a common technique for obfuscating malicious scripts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Encoded Command with Shortened Parameter
    description: Detects PowerShell processes using shortened variations of the EncodedCommand parameter to execute Base64-encoded commands.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-05-11T22:05:43Z"
    level: L2
    summary: poc_available; added CVE-2022-26923 +1; OS windows
    sources:
      - unit42
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-59287; KEV CVE-2022-26923
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Attackers frequently use the PowerShell `EncodedCommand` parameter to obfuscate malicious scripts, making detection challenging. This technique allows for the execution of Base64-encoded commands, effectively hiding the true nature of the script from cursory inspection. Defenders should be wary of PowerShell processes using `EncodedCommand` because successful exploitation can lead to unauthorized access, privilege escalation, and persistent threats. This behavior has been observed across various campaigns, including those targeting SolarWinds WHD (post-exploitation), Ukraine (WhisperGate), and US critical infrastructure (Volt Typhoon). The CVE-2025-59287, affecting Microsoft WSUS, also highlights the risk of PowerShell-based attacks.

## Attack Chain

1. Initial Access: The attacker gains initial access through various means, such as exploiting a vulnerability or using stolen credentials.
2. PowerShell Execution: PowerShell is invoked on the compromised system.
3. EncodedCommand Parameter: The attacker uses the `-EncodedCommand` (or shortened variations) parameter to pass a Base64-encoded script to PowerShell.
4. Obfuscation: The encoded script contains malicious commands that are obfuscated to avoid detection by signature-based antivirus solutions.
5. Payload Delivery: The decoded script executes, downloading and installing a secondary payload, such as a backdoor or remote access trojan (RAT).
6. Privilege Escalation: The payload attempts to escalate privileges on the system, potentially using techniques like exploiting vulnerable services or bypassing User Account Control (UAC).
7. Lateral Movement: With elevated privileges, the attacker moves laterally to other systems on the network, often using techniques like Pass-the-Hash or Pass-the-Ticket.
8. Objective Achieved: The attacker achieves their objective, such as data exfiltration, ransomware deployment, or system disruption.

## Impact

Successful exploitation can result in a range of impacts, including unauthorized access to sensitive data, the deployment of ransomware, and the disruption of critical services. Organizations across various sectors have been targeted, including critical infrastructure (Volt Typhoon) and government entities (WhisperGate). A single successful attack can cost millions of dollars in recovery efforts, lost productivity, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Detect PowerShell Encoded Command` to your SIEM to identify suspicious PowerShell processes using the `EncodedCommand` parameter and tune for your environment.
*   Enable Sysmon process-creation logging to capture the command-line arguments of PowerShell processes, which is required for the Sigma rule above.
*   Investigate any alerts generated by the Sigma rule `Detect PowerShell Encoded Command` to determine if the activity is malicious.
*   Patch CVE-2025-59287 on all affected Windows systems, especially WSUS servers, to prevent exploitation via PowerShell-based attacks.
