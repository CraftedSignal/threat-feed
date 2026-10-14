---
title: Local Privilege Escalation in MyReport Updater via DLL Hijacking
slug: 2026-10-myreport-updater-lpe
description: MyReport Updater versions through 2.1.1 are vulnerable to local privilege escalation allowing low-privileged users to achieve SYSTEM execution via malicious DLL injection in osk.exe.
date: "2026-10-14T16:37:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:myreport:updater:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - lpe
  - cve-2026-110633
vendors:
  - MyReport
products:
  - MyReport Updater (<= 2.1.1)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: The vulnerability allows installing malicious archives and planting a DLL like HID.dll loaded by osk.exe to gain SYSTEM privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574.002
    technique_name: 'Hijack Execution Flow: DLL Search Order Hijacking'
    evidence: Attackers can use UpdaterManager.exe to set a malicious reference server and installLocation, planting a DLL like HID.dll.
    confidence_band: high
cves:
  - id: CVE-2026-110633
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110633
rules:
  - title: Detect CVE-2026-110633 Exploitation - DLL Hijacking via osk.exe
    description: Detects osk.exe loading HID.dll from an unexpected directory, potentially indicating DLL hijacking exploitation
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch MyReport Updater on all Windows hosts to version 2.1.2 or later
      owner: IT Operations
      due: 48h
      evidence: Source states versions through 2.1.1 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Deploy image load detection rule for osk.exe dependency loading
      owner: Detection Engineering
      addresses: CVE-2026-110633
      evidence: TTP of DLL hijacking via osk.exe identified
---

MyReport Updater through version 2.1.1 contains a local privilege escalation (LPE) vulnerability (CVE-2026-110633) stemming from insecure gRPC communication handled by the UpdaterManager.exe service. This service, which runs with SYSTEM privileges, fails to properly validate the reference server and installLocation parameters provided by users over the gRPC interface. An unprivileged attacker can exploit this flaw to instruct the service to download and extract a malicious archive into an arbitrary filesystem directory. By specifying an install location that enables DLL hijacking, the attacker can place a malicious version of HID.dll such that it is subsequently loaded by the On-Screen Keyboard process (osk.exe) when it initiates under a SYSTEM context. This allows the attacker to transition from a low-privileged user account to full system-level access.

## Impact

Successful exploitation allows a local user to gain SYSTEM privileges on the affected host. This vulnerability has a CVSS v3.1 base score of 7.8, representing a significant risk in multi-user or shared workstation environments where MyReport Updater is deployed. Organizations using versions 2.1.1 and earlier are at risk of complete system compromise if an unprivileged user gains local access to the system.

## Recommendation

- Upgrade all instances of MyReport Updater to a version beyond 2.1.1 immediately.
- Monitor for unauthorized gRPC communication directed at UpdaterManager.exe from non-privileged user accounts.
- Audit filesystem permissions on critical directories to prevent local users from writing DLLs to paths where system processes load dependencies.
- Use EDR/Sysmon telemetry to baseline legitimate dependency loading for system binaries like osk.exe.
