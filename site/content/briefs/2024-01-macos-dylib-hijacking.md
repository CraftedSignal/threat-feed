---
title: macOS Local Privilege Escalation via Dylib Hijacking in App Store Applications
slug: 2024-01-macos-dylib-hijacking
description: A local privilege escalation vulnerability in macOS allows attackers to gain root privileges by hijacking dylibs in applications installed from the Mac App Store.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dylib-hijacking
  - privilege-escalation
  - macos
vendors:
  - Tresorit
  - Avira
  - Microsoft
  - Objective-See
  - FireEye
products:
  - Tresorit
  - MS Office 2016
  - Monitor.app
  - ProcInfoExample
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://objective-see.org/blog/blog_0x46.html
rules:
  - title: Detecting Dylib Hijacking via DYLD_PRINT_RPATHS
    description: Detects when the DYLD_PRINT_RPATHS environment variable is set, which is often used to identify vulnerable dylibs.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
  - title: Detecting Suspicious Dylib Loading
    description: Detects when a dylib is loaded from a non-standard location, potentially indicating a hijacking attempt.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - macos
  - title: Detecting createHijacker.py execution
    description: Detects execution of the `createHijacker.py` script, used to configure malicious dylibs for hijacking.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - process_creation
      - macos
rules_count: 3
---

This brief addresses a local privilege escalation vulnerability in macOS that leverages dylib hijacking within applications obtained from the official Mac App Store. The vulnerability allows a malicious actor to inject a dynamic library (dylib) into a legitimate application, potentially gaining elevated privileges. The attack exploits weaknesses in how macOS applications load dynamic libraries, specifically the use of weak loading and run-path dependent (rpath) dylibs. While applications dragged into the /Applications directory are typically owned by the user, applications installed from the App Store are owned by root, requiring privilege escalation to exploit. This vulnerability matters because it allows attackers to bypass intended security restrictions and gain root access, even on systems with standard security configurations. Successful exploitation enables persistence and further malicious activities.

## Attack Chain

1.  The attacker identifies a vulnerable application using tools like Dylib Hijack Scanner (DHS), looking for apps with weak or rpath-dependent dylib loading.
2.  The attacker confirms the absence of library-validation option (flag=0x200) using `codesign` to verify if dylib hijacking is possible.
3.  The attacker crafts a malicious dylib (e.g., `hello-tresorit.dylib`) containing code to be executed upon loading, such as opening a Terminal or creating a syslog entry.
4.  The attacker uses `gcc` to compile the dylib. The attacker uses a tool like `createHijacker.py` to fix the dylib version and add exports from the original dylib to the malicious dylib.
5.  The attacker exploits a vulnerability to bypass root folder permissions to copy the malicious dylib to the application's framework directory (e.g., `/Applications/Tresorit.app/Contents/MacOS/TresoritExtension.app/Contents/PlugIns/FinderExtension.appex/Contents/MacOS/../../../../Frameworks/UtilsMac.framework/Versions/A/UtilsMac`).
6.  The attacker launches the targeted application, causing the malicious dylib to be loaded into the application process.
7.  The malicious code within the dylib executes with the privileges of the application, potentially escalating privileges to root.
8.  The attacker achieves persistence or performs other malicious actions based on the gained privileges.

## Impact

Successful exploitation of this vulnerability can lead to complete system compromise. An attacker gaining root access can install persistent backdoors, steal sensitive data, or deploy ransomware. The number of potential victims is large, as many macOS applications from the App Store are vulnerable. The affected sectors span various industries, as the vulnerability affects a wide range of applications. The consequences of a successful attack range from data breaches and financial loss to complete system control by the attacker.

## Recommendation

*   Use a tool like Dylib Hijack Scanner to identify vulnerable applications in your environment and prioritize patching or removal.
*   Monitor for the creation of new dylibs within application framework directories, which may indicate a dylib hijacking attempt, using a file integrity monitoring system.
*   Deploy the Sigma rule `Detecting Dylib Hijacking via DYLD_PRINT_RPATHS` to detect attempts to identify vulnerable dylibs.
*   Enable library validation for applications to prevent the loading of unsigned or improperly signed dylibs.
*   Use process monitoring tools like Objective-See's ProcInfo to detect suspicious process creation events that may be indicative of exploitation.
