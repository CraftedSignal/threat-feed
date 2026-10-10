---
title: Android PackageInstallerService Update Ownership Bypass
slug: 2026-10-android-update-ownership-bypass
description: CVE-2026-0023 allows a malicious installer to suppress security warnings by manipulating internal installation flags, potentially facilitating the installation of malicious updates for legitimate applications.
date: "2026-10-10T06:53:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:google:android:14.0:*:*:*:*:*:*:*
  - cpe:2.3:o:google:android:15.0:*:*:*:*:*:*:*
  - cpe:2.3:o:google:android:16.0:*:*:*:*:*:*:*
tags:
  - android
  - vulnerability
  - security-bypass
  - mobile
vendors:
  - Google
products:
  - Android (14.0, 15.0, 16.0)
affected_os:
  - Android 14.0
  - Android 15.0
  - Android 16.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This repository demonstrates how CVE-2026-0023 allows a regular installer to influence an internal Android installation flag that should be managed only by the system.
    confidence_band: high
cves:
  - id: CVE-2026-0023
    cvss: 7.8
    epss: 0.00085
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-QM4RS-CVE-2026-0023-UPDATE-OWNERSHIP-POC
  - https://github.com/ChickenHook/RestrictionBypass
action_plan:
  priority: elevated
  owners:
    - SOC
    - Mobile Security Team
  immediate_actions:
    - action: Patch all Android endpoints to security patch level 2026-03-05 or later to address CVE-2026-0023.
      owner: Mobile Security Team
      due: 72h
      evidence: CVE-2026-0023 is addressed in the Android security bulletin for March 2026.
  mitigation_plan:
    - priority: immediate
      action: Restrict installation of applications from unknown or unauthorized sources via MDM.
      owner: Mobile Security Team
      addresses: CVE-2026-0023
      evidence: The vulnerability relies on a malicious installer to bypass security checks.
---

CVE-2026-0023 is a security vulnerability in the Android PackageInstallerService, specifically within the `createSessionInternal` method. The vulnerability arises from the improper handling of the internal installation flag `INSTALL_FROM_MANAGED_USER_OR_PROFILE`. In vulnerable Android 14.0, 15.0, and 16.0 builds, this flag is not explicitly cleared during the session creation process. 

Android utilizes an "update ownership" mechanism to notify users when an application is being updated by a source other than the original installer. By failing to clear the flag, a malicious application acting as an installer can manipulate the OS into bypassing this critical security warning. Instead of the expected alert identifying the update source, the user is presented with a generic, less restrictive update confirmation dialog. This behavior allows attackers to potentially replace legitimate applications with malicious versions while avoiding user scrutiny. The issue was addressed in the March 2026 Android security patch level.

## Attack Chain

1. The attacker deploys a malicious application masquerading as a legitimate installer or package management utility.
2. The malicious application initiates a package installation session via `PackageInstallerService#createSessionInternal`.
3. The attacker crafts the installation session parameters to exploit the failure to clear the `INSTALL_FROM_MANAGED_USER_OR_PROFILE` flag.
4. The Android OS incorrectly evaluates the session, assuming it originates from a managed environment due to the uncleared flag.
5. The OS bypasses the check that would normally trigger the "update ownership" warning dialog.
6. The system displays a generic, non-specific update confirmation dialog to the user.
7. The user, unaware that the update source has been switched, authorizes the installation of the malicious package update.

## Impact

Successful exploitation of CVE-2026-0023 allows attackers to deceive users regarding the source of application updates. This undermines the Android update ownership trust chain, increasing the risk of unauthorized application replacement or the installation of malicious software under the guise of legitimate updates. The vulnerability affects a broad range of Android versions (14.0 through 16.0), potentially exposing a significant portion of the global Android user base to targeted application hijacking.

## Recommendation

Prioritized actions for security teams:
- Identify and audit all devices running Android 14.0, 15.0, and 16.0 within the environment.
- Ensure all managed mobile devices have received the Android security patch level of 2026-03-05 or later to resolve CVE-2026-0023.
- Implement mobile device management (MDM) policies to restrict the installation of applications from unknown or untrusted sources.
- Monitor for unusual installation activities on managed Android devices that correlate with unauthorized or suspicious package installers.
