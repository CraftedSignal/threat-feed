---
title: Microsoft September 2026 Patch Tuesday Addresses Two Actively Exploited Zero-Days
slug: 2026-09-microsoft-patch-tuesday
description: Microsoft's September 2026 update cycle addresses 974 vulnerabilities, including two privilege-escalation zero-days actively exploited in the wild and 20 potentially wormable RCE flaws.
date: "2026-09-08T20:04:20Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
tags:
  - vulnerability-management
  - patch-tuesday
  - windows
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Windows
  - Office 2016
  - SQL Server
  - SharePoint Server
  - Azure
  - Skype for Business
  - Exchange Server
  - Authenticator
affected_os:
  - Windows Server 2012
  - Windows Server 2012 R2
  - Windows 10 Version 1607
  - Windows Server 2016
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The record-breaking September security update fixes two exploited privilege-escalation zero-days.
    confidence_band: high
cves:
  - id: CVE-2026-85880
    cvss: 7.8
  - id: CVE-2026-81963
    cvss: 7.8
references:
  - https://www.securityweek.com/microsoft-patches-record-974-vulnerabilities-including-two-exploited-zero-days/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Deploy September 2026 Microsoft security updates immediately, prioritizing CVE-2026-85880 and CVE-2026-81963.
      owner: IT Operations
      due: 24h
      evidence: Microsoft security update advisory for September 2026
  mitigation_plan:
    - priority: immediate
      action: Patch Windows environments against CVE-2026-85880 and CVE-2026-81963.
      owner: IT Operations
      addresses: CVE-2026-85880, CVE-2026-81963
      evidence: Actively exploited in the wild
---

Microsoft's September 2026 Patch Tuesday release is a record-breaking update addressing 974 distinct vulnerabilities across its product ecosystem. Of critical concern are two zero-day vulnerabilities (CVE-2026-85880 and CVE-2026-81963) that are confirmed to be under active exploitation in the wild. Both flaws allow local attackers to escalate their privileges to System. Additionally, the release addresses 20 potentially wormable vulnerabilities that enable unauthenticated remote code execution (RCE) without user interaction, increasing the risk of widespread automated exploitation within enterprise networks.

The update covers a wide range of products including Windows, Office (specifically 2016), SQL Server, SharePoint Server, Azure, Skype for Business, and Exchange Server. Security teams are advised to prioritize remediation based on reachability and exposure, specifically for the 20 wormable RCE flaws and the two actively exploited zero-days.

## Impact

Successful exploitation of the zero-day vulnerabilities allows local attackers to achieve System-level privilege escalation, granting full control over the compromised host. The 20 identified wormable vulnerabilities pose a significant threat to organizational integrity, as they allow for unauthenticated RCE, potentially facilitating the rapid spread of malware or ransomware across internal network segments without user intervention. The broad scope of affected products, including critical infrastructure components like Exchange and SharePoint, necessitates an urgent patching cadence to mitigate the elevated risk of unauthorized access and lateral movement.

## Recommendation

- Prioritize immediate patching of the two exploited zero-days (CVE-2026-85880 and CVE-2026-81963) across all affected Windows endpoints.
- Review the 20 identified wormable RCE vulnerabilities for systems that are internet-facing or have high network exposure and apply security updates as the highest priority.
- Apply the latest Servicing Stack Updates (SSU) to Windows Server 2012, 2012 R2, Windows 10 (1607), and Windows Server 2016 immediately to ensure system integrity.
- Monitor logs for unusual process escalation attempts or unexpected updates to the Windows Update Stack components that could indicate exploitation of CVE-2026-81963.
