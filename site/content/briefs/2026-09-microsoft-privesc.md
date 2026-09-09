---
title: Multiple Privilege Escalation Vulnerabilities in Microsoft Authenticator and Xbox Gaming Services
slug: 2026-09-microsoft-privesc
description: Local attackers can exploit multiple vulnerabilities in Microsoft Authenticator and Xbox Gaming Services to achieve elevated privileges on Windows systems.
date: "2026-09-09T12:53:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - windows
  - vulnerability
vendors:
  - Microsoft
products:
  - Microsoft Authenticator
  - Xbox Gaming Services
affected_os:
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker can exploit multiple vulnerabilities in Microsoft Authenticator and Microsoft Xbox Gaming Services to elevate their privileges.
    confidence_band: high
cves:
  - id: CVE-2024-38063
    cvss: 9.8
    epss: 0.70564
  - id: CVE-2024-38060
    cvss: 8.8
    epss: 0.15908
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3241
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Patch Microsoft Authenticator and Xbox Gaming Services to latest versions containing fixes for CVE-2024-38063 and CVE-2024-38060
      owner: IT Operations
      addresses: CVE-2024-38063, CVE-2024-38060
      evidence: Source advisory recommends remediation via vendor updates
---

Microsoft has disclosed multiple security vulnerabilities affecting Microsoft Authenticator and Microsoft Xbox Gaming Services on Windows. These flaws, identified as CVE-2024-38063 and CVE-2024-38060, allow a local, authenticated attacker to perform privilege escalation. By successfully exploiting these vulnerabilities, an attacker with low-privileged access to a system can elevate their permissions, potentially gaining administrative access. These issues pose a significant risk to organizational security, as they facilitate lateral movement or deeper system compromise following an initial access event. Defenders should prioritize patching all systems running these Microsoft applications to the latest available security updates to mitigate the risk of local exploitation.

## Impact

Successful exploitation of these vulnerabilities allows a local attacker to escalate privileges on Windows 10 and Windows 11 systems. This could lead to full system compromise, unauthorized access to sensitive data, and persistence establishment. Organizations utilizing these services on endpoint devices are at risk if an attacker has already gained initial local access to the machine.

## Recommendation

Prioritize the immediate application of security patches provided by Microsoft for all affected installations of Authenticator and Xbox Gaming Services to remediate CVE-2024-38063 and CVE-2024-38060. Verify that automated update mechanisms for these components are functioning as expected across the environment.
