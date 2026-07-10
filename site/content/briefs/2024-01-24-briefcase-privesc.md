---
title: Briefcase MSI Installer Privilege Escalation Vulnerability
slug: 2024-01-24-briefcase-privesc
description: Briefcase versions 0.3.0 to 0.3.25 create an insecure directory during Windows MSI installer creation, leading to potential privilege escalation by allowing low-privilege users to modify binaries that may be executed by administrators.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - briefcase
  - privilege-escalation
  - windows
  - msi
vendors:
  - BeeWare
products:
  - Briefcase
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-r3r2-35v9-v238
  - https://github.com/beeware/briefcase-windows-app-template/pull/86
  - https://github.com/beeware/briefcase-windows-VisualStudio-template/pull/85
  - https://github.com/beeware/briefcase/issues/2759
rules:
  - title: Detect Execution of Modified Binaries in Program Files
    description: Detects execution of binaries in Program Files that have been recently modified, indicating a potential binary replacement attack due to insecure permissions.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Briefcase Application Installation Directory Creation with Insecure Permissions
    description: Detects the creation of directories by msiexec.exe with potential insecure permissions related to Briefcase installer vulnerability.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Briefcase application, a tool used for converting Python projects into standalone executables, contains a vulnerability in versions 0.3.0 through 0.3.25. When creating Windows MSI installers for "All Users" (per-machine) installations, the generated installer creates a directory that inherits the permissions of its parent. This insecure permission inheritance allows a low-privilege, authenticated user to potentially modify or replace the installed application binaries. If an administrator later executes these compromised binaries, they would run with elevated privileges, leading to a privilege escalation. The vulnerability stems from the WXS file template used during the MSI creation process. Patches have been released in Briefcase versions 0.3.26, 0.4.0, and 0.4.1 which update the WXS templates used during project creation to correct the insecure directory permissions. This vulnerability was reported as beeware/briefcase#2759 and assigned CVE-2026-33430.

## Attack Chain

1.  A developer uses Briefcase (versions 0.3.0 - 0.3.25) to create a Windows MSI installer for a Python project intended to be installed for "All Users" (per-machine).
2.  The MSI installer is executed, creating a directory (e.g., within `C:\Program Files\`) for the application binaries. Due to the vulnerable WXS template, this directory inherits insecure permissions from its parent directory.
3.  A low-privilege, authenticated user identifies the insecurely permissioned directory created by the MSI installer.
4.  The attacker replaces a legitimate application binary (e.g., `app.exe`) within the directory with a malicious executable.
5.  An administrator or privileged user executes the compromised application binary (`app.exe`) directly or indirectly (e.g., via a scheduled task or shortcut).
6.  The malicious executable runs with the elevated privileges of the user who executed it.
7.  The attacker performs malicious actions with elevated privileges, such as installing malware, creating new accounts, or modifying system configurations.
8.  The attacker achieves persistent access and control over the compromised system.

## Impact

Successful exploitation of this vulnerability allows a low-privilege user to gain elevated privileges on a Windows system. The insecure directory permissions created during installation allow malicious users to replace legitimate application binaries with malicious ones. This can lead to complete system compromise, data theft, or denial of service. The vulnerability affects any application built with vulnerable versions of Briefcase and installed for all users on a Windows system. If the compromised application is critical to business operations, the impact could be significant.

## Recommendation

*   Upgrade Briefcase to version 0.3.26, 0.4.0, or 0.4.1, or later and rebuild the affected Windows MSI installers. This will ensure that the updated WXS templates are used, correcting the insecure directory permissions (beeware/briefcase-windows-app-template#86, beeware/briefcase-windows-VisualStudio-template#85).
*   For existing Briefcase projects, apply the change from beeware/briefcase-windows-app-template#86 to the .wxs file.
*   Monitor process creation events for execution of binaries from within `C:\Program Files\` or `C:\Program Files (x86)\` that do not match expected application signatures or have been recently modified, using the provided Sigma rule.
*   Review existing installations of applications built with Briefcase versions 0.3.0 - 0.3.25 for insecure directory permissions and remediate by reinstalling the application with an updated installer or manually correcting the permissions.
