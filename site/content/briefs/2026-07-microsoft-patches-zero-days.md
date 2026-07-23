---
title: Microsoft Addresses Two Actively Exploited Zero-Day Vulnerabilities in July 2026 Patch Tuesday
slug: 2026-07-microsoft-patches-zero-days
description: Microsoft's July 2026 Patch Tuesday addressed 622 vulnerabilities, including two actively exploited zero-day elevation of privilege flaws, CVE-2026-56155 in Active Directory Federation Services and CVE-2026-56164 in SharePoint, allowing local and remote attackers to gain administrative control.
date: "2026-07-21T03:36:29Z"
lastmod: "2026-07-23T20:49:20Z"
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
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:subscription:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:-:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:-:*:x64:*
has_poc: true
tags:
  - patch-tuesday
  - zero-day
  - vulnerability
  - microsoft
  - windows
  - sharepoint
  - active-directory-federation-services
  - bitlocker
  - elevation-of-privilege
  - security-feature-bypass
vendors:
  - Microsoft
products:
  - Active Directory Federation Services
  - Microsoft SharePoint
  - Windows BitLocker
  - Windows User Profile Service
  - Microsoft Windows
  - Microsoft Office
  - Windows VMSwitch
  - Microsoft SharePoint Server
  - Microsoft Windows VMSwitch
  - IIS
  - Windows
  - SharePoint
  - Office
  - SharePoint Server
  - Extended Security Updates
  - Extended Security Updates (ESU)
  - Windows User Profile Service (all currently supported Windows desktop and server versions)
  - Active Directory Federation Services (AD FS)
  - Microsoft Active Directory Federation Services
  - Microsoft BitLocker
  - Microsoft Windows User Profile Service
affected_os:
  - Windows
  - Windows Server
  - Windows desktop and server versions
  - Windows Desktop
  - Windows server versions
  - Windows desktop versions
  - all currently supported Windows desktop and server versions
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An insufficient granularity of access control flaw (CWE-1220) allows a low-privileged local attacker to elevate privileges with no user interaction and low attack complexity. Successful exploitation could grant an attacker administrator privileges.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A missing authentication for a critical function flaw (CWE-306) allows an unauthenticated remote attacker to elevate privileges over a network with no user interaction and low attack complexity.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A missing authentication for a critical function flaw (CWE-306) allows an unauthenticated remote attacker to elevate privileges over a network with no user interaction and low attack complexity.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: A protection mechanism failure flaw (CWE-693) allows an unauthenticated attacker with physical access to bypass BitLocker Device Encryption and gain access to encrypted data on the system storage device.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: unpatched privilege escalation vulnerability affecting the Windows User Profile Service (profsvc)... ability for a standard user to abuse the service's hive loading mechanism to mount arbitrary registry hives with elevated privileges by coercing the User Profile Service, which operates at SYSTEM integrity, into loading an attacker-controlled hive file.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: Successful exploitation could enable registry-based persistence
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Successful exploitation could enable ... credential theft
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: Successful exploitation could enable ... security product tampering.
    confidence_band: high
cves:
  - id: CVE-2026-56155
    cvss: 7.8
    epss: 0.00379
  - id: CVE-2026-56164
    cvss: 5.3
    epss: 0.05601
  - id: CVE-2026-50661
    cvss: 6.1
    epss: 0.00381
  - id: CVE-2026-57092
    cvss: 9.9
    epss: 0.00988
references:
  - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-july-2026/
iocs:
  - type: other
    value: GreatXML
  - type: other
    value: LegacyHive
  - type: other
    value: MSNightmare
  - type: other
    value: Nightmare-Eclipse
ioc_counts:
  other: 4
updates:
  - at: "2026-07-22T07:20:24Z"
    level: L1
    summary: OS all currently supported windows desktop and server versions
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-july-2026/
  - at: "2026-07-22T11:11:02Z"
    level: L2
    summary: extended security updates version ESU
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-july-2026/
  - at: "2026-07-23T12:38:02Z"
    level: L2
    summary: windows user profile service version all currently supported Windows desktop and server versions
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-july-2026/
  - at: "2026-07-23T20:08:39Z"
    level: L2
    summary: active directory federation services version AD FS
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-july-2026/
  - at: "2026-07-23T20:49:20Z"
    level: L1
    summary: new product
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-july-2026/
---

Microsoft released its July 2026 Patch Tuesday updates, addressing a total of 622 vulnerabilities, a significant increase from previous months. This release includes fixes for two zero-day vulnerabilities (CVE-2026-56155 and CVE-2026-56164) confirmed to be under active exploitation in the wild. CVE-2026-56155 is an Important elevation of privilege flaw in Active Directory Federation Services (AD FS) with a CVSS score of 7.8, allowing local privilege escalation without user interaction. CVE-2026-56164 is a Moderate elevation of privilege vulnerability in Microsoft SharePoint, with a CVSS score of 5.3, enabling unauthenticated remote attackers to gain privileges over the network. Additionally, one publicly disclosed but unexploited zero-day (CVE-2026-50661) affects Windows BitLocker, bypassing device encryption. CrowdStrike's Counter Adversary Operations Advanced Research Team discovered four of the patched CVEs. An unpatched privilege escalation vulnerability affecting the Windows User Profile Service was also disclosed shortly after the Patch Tuesday release, with a PoC exploit named LegacyHive, enabling potential registry-based persistence, credential theft, or security product tampering. This extensive update package underscores the critical need for prompt patching to mitigate active and potential threats.

## Impact

Successful exploitation of the actively exploited CVE-2026-56155 in Active Directory Federation Services could grant a low-privileged local attacker administrator privileges, potentially leading to full system compromise. The exploited CVE-2026-56164 in Microsoft SharePoint allows unauthenticated remote attackers to elevate privileges over a network, posing a significant risk to data integrity and system access. The publicly disclosed CVE-2026-50661, a BitLocker bypass, permits an unauthenticated attacker with physical access to gain access to encrypted data on the storage device. The unpatched Windows User Profile Service vulnerability, if exploited, could enable attackers to establish registry-based persistence, steal credentials, or tamper with security products, affecting all currently supported Windows desktop and server versions. The wide range of affected products, including Microsoft Windows, Extended Security Updates (ESU), and Microsoft Office, indicates a broad potential impact across enterprise environments, with elevation of privilege and remote code execution being the most prevalent risk types.

## Recommendation

* **Patch CVE-2026-56155 and CVE-2026-56164 immediately** on all affected Active Directory Federation Services and Microsoft SharePoint installations, respectively, as they are actively exploited zero-days.
* **Apply patches for CVE-2026-50661** to mitigate the Windows BitLocker security feature bypass vulnerability.
* **Ensure Anti-Malware Scan Interface (AMSI) is actively integrated** and scanning SharePoint and IIS worker process memory, with Request Body Scan mode set to Full, as a pre-patch mitigation for CVE-2026-56164.
* **Monitor Microsoft's official channels for an upcoming patch** for the unpatched privilege escalation vulnerability affecting the Windows User Profile Service.
