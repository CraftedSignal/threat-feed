---
title: Privilege Escalation Vulnerability in Microsoft Windows Package Manager
slug: 2026-08-windows-package-manager-lpe
description: A local privilege escalation vulnerability in the Microsoft Windows Package Manager allows an authenticated local attacker to gain elevated privileges on the host system.
date: "2026-08-12T10:17:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022_23h2:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - windows
  - vulnerability
vendors:
  - Microsoft
products:
  - Windows Package Manager
affected_os:
  - Windows
cves:
  - id: CVE-2024-38062
    cvss: 7.8
    epss: 0.01612
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2785
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Patch Windows Package Manager across the enterprise
      owner: IT Operations
      addresses: CVE-2024-38062
      evidence: Source advisory recommends addressing the privilege escalation flaw.
---

Microsoft has disclosed a security vulnerability affecting the Windows Package Manager (winget) that facilitates local privilege escalation. This issue, tracked as CVE-2024-38062, allows a local, authenticated user to exploit flaws within the package manager's execution or installation logic to execute code with elevated permissions. Because the Windows Package Manager is a central component for managing system software, this vulnerability poses a risk to system integrity in environments where non-administrative users are permitted to execute package management commands or where automated deployment scripts interact with the tool. Defenders should prioritize patching, as this vulnerability requires local access to a system to successfully trigger the escalation.

## Impact

Successful exploitation of this vulnerability enables an attacker with local access to elevate their account privileges. This can result in complete system compromise, unauthorized access to sensitive data, and the ability to install persistent malware. The vulnerability affects all systems utilizing the Microsoft Windows Package Manager on supported versions of Windows.

## Recommendation

* Apply the security updates provided by Microsoft for the Windows Package Manager component to address CVE-2024-38062.
* Audit environments to identify the presence and version of the Windows Package Manager.
* Review system logs for unusual package installations or unexpected process executions originating from the winget.exe process.
