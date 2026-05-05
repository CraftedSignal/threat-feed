---
title: Detection of Windows RMM Tool Execution
slug: 2024-01-rmm-tool-execution
description: Detects process creation events indicative of remote management tools, potentially signifying legitimate use or malicious exploitation by threat actors abusing RMM software.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - rmm
  - remote-access
  - sysmon
vendors:
  - AmidaWare
  - Ammyy LLC
  - AnyDesk Software
  - ATERA Networks
  - Bomgar
  - FleetDeck
  - GoTo
  - IDrive Inc
  - LogMeIn, Inc
  - MMSOFT Design
  - N-able
  - NetSupport Ltd
  - NinjaRMM
  - Remote Utilities
  - SimpleHelp
  - Servably
  - ScreenConnect
  - Splashtop
  - TeamViewer Germany
  - ZOHO Corporation
products:
  - AnyDesk
  - Ammyy Admin
  - AteraAgent
  - BeyondTrust Remote Support
  - FleetDeck
  - GoToAssist
  - GoToMyPC
  - Kaseya Live Connect
  - N-able
  - NetSupport Client Application
  - NinjaRMM
  - Pulseway
  - RemotePC
  - Remote Utilities
  - ScreenConnect
  - SimpleHelp Remote
  - Splashtop
  - Tactical RMM Agentz
  - Take Control Agent
  - Zoho Assist
  - NetSupport Remote Control
  - NetSupport Manager
  - Remote Access
  - Remote Support
  - Syncro
  - TeamViewer
  - ZohoMeeting
  - rustdesk.exe
  - tailscale
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://github.com/LivingInSyn/RMML/tree/main/RMMs
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
  - https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects
rules:
  - title: Detect AnyDesk Process Creation
    description: Detects the execution of AnyDesk based on process name.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect ScreenConnect Process Creation
    description: Detects ScreenConnect execution based on process name.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect Tactical RMM Agent Execution
    description: Detects Tactical RMM Agent execution via image name
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This brief focuses on detecting the execution of Remote Monitoring and Management (RMM) tools on Windows systems. RMM software, while legitimate for IT administration, can be abused by threat actors for unauthorized access and control. This detection leverages process creation events (Sysmon Event ID 1) and identifies processes associated with various RMM vendors and products. The detection aims to provide visibility into the usage of these tools, allowing security teams to differentiate between legitimate administrative activities and potentially malicious operations. This analysis is based on a detection rule published on GitHub, last updated in April 2026. Defenders should be aware of the potential for false positives due to legitimate RMM usage.

## Attack Chain

1.  Initial Access: A threat actor gains initial access to a Windows system through various means, such as phishing or exploiting a vulnerability.
2.  RMM Tool Deployment: The attacker deploys an RMM tool onto the compromised system. This might involve downloading an executable or using existing administrative privileges to install the software.
3.  Process Creation: The RMM tool's executable is launched, triggering a process creation event (Sysmon Event ID 1). For example, `AnyDesk.exe` or `TeamViewer.exe` starts.
4.  Remote Access Established: The RMM tool establishes a remote connection to the attacker's command and control (C2) server.
5.  Credential Theft: The attacker leverages the RMM tool to gain elevated privileges or steal credentials.
6.  Lateral Movement: Using the compromised system and stolen credentials, the attacker moves laterally within the network.
7.  Data Exfiltration: The attacker uses the RMM tool's file transfer capabilities to exfiltrate sensitive data from the compromised network.
8.  Persistence: The attacker configures the RMM tool to maintain persistent access to the compromised system.

## Impact

Successful exploitation via RMM tools can lead to significant damage, including data breaches, financial loss, and reputational damage. Threat actors can use these tools to remotely control systems, steal sensitive information, and deploy ransomware. The impact can range from individual system compromise to enterprise-wide breaches affecting thousands of systems. Organizations in various sectors are vulnerable, especially those with weak endpoint security and inadequate monitoring of RMM tool usage.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) to capture process execution events, which is crucial for triggering the detections.
*   Deploy the "Windows RMM Tool Execution" detection rule to your SIEM and tune it for your environment to reduce false positives, referencing the search query provided in the content.
*   Investigate any alerts generated by the "Windows RMM Tool Execution" detection rule, prioritizing alerts involving unusual user accounts or systems.
*   Implement a process whitelisting policy to restrict the execution of unauthorized RMM tools and software.
*   Monitor network connections originating from processes identified in the detection rule to identify potential command and control activity.
*   Review the references provided in the content, specifically the CISA advisory (https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a), for additional mitigation strategies.
