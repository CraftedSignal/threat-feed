---
title: DLL Hijacking Vulnerabilities in Rockwell Automation Redundancy Module Configuration Tool
slug: 2026-09-rockwell-redundancy-tool-vulnerabilities
description: Rockwell Automation Redundancy Module Configuration Tool versions 9.x and 10.00.00 are vulnerable to DLL hijacking, potentially allowing local privilege escalation to SYSTEM level.
date: "2026-09-01T17:11:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rockwellautomation:redundancy_module_configuration_tool:9.00.00:*:*:*:*:*:*:*
  - cpe:2.3:a:rockwellautomation:redundancy_module_configuration_tool:10.00.00:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - dll-hijacking
  - industrial-control-systems
  - windows
vendors:
  - Rockwell Automation
products:
  - Redundancy Module Configuration Tool (10.00.00)
  - Redundancy Module Configuration Tool (>=9.00.00 and <=10.00.00)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The RM3ConfigTool.exe binary searches directories in the system path for a required DLL, and one or more of these directories may be writable by standard users.
    confidence_band: high
cves:
  - id: CVE-2026-9633
  - id: CVE-2026-9634
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-244-02
  - https://www.cve.org/CVERecord?id=CVE-2026-9633
  - https://www.cve.org/CVERecord?id=CVE-2026-9634
rules:
  - title: Detect DLL Hijacking via Unusual Image Load
    description: Detects an application loading a DLL from a suspicious directory, which may indicate a DLL hijacking attempt against Rockwell tools.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574.001
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
    - action: Upgrade all instances of Redundancy Module Configuration Tool to 10.01.00
      owner: IT Operations
      due: 72h
      evidence: Vendor fix provided in source
  mitigation_plan:
    - priority: immediate
      action: Review and remediate directory permissions on all systems running the affected tool
      owner: IT Operations
      addresses: CVE-2026-9633, CVE-2026-9634
      evidence: Source mitigation guidance
---

Rockwell Automation has disclosed two local privilege escalation vulnerabilities (CVE-2026-9633 and CVE-2026-9634) affecting the Redundancy Module Configuration Tool. The vulnerabilities arise from insecure directory permissions in the system path. Because the RM3ConfigTool.exe and RMConfigTool.exe binaries perform insecure library loading by searching for required DLLs in locations writable by standard users, a local attacker can plant a malicious DLL. When an administrator subsequently executes the tool, the malicious library is loaded into the elevated process context, resulting in code execution with Administrator or SYSTEM privileges. These vulnerabilities are limited to local exploitation and require a user with standard privileges to perform the initial file placement. Users are advised to upgrade to version 10.01.00 immediately.

## Attack Chain

1. Attacker gains local access to the Windows workstation where the Redundancy Module Configuration Tool is installed.
2. Attacker identifies a directory in the system PATH that is writable by non-administrator users.
3. Attacker crafts a malicious DLL that mimics the name of a library required by the target application (RM3ConfigTool.exe or RMConfigTool.exe).
4. Attacker writes the malicious DLL to the identified writable directory.
5. An administrator account logs onto the system or initiates the configuration tool.
6. The target application performs a DLL search and loads the malicious library from the attacker-controlled location.
7. Malicious code executes within the context of the elevated process (SYSTEM or Administrator).

## Impact

Successful exploitation allows a local, non-privileged attacker to escalate privileges to Administrator or SYSTEM level on the host system. This could lead to full system compromise, exfiltration of sensitive configuration data, or manipulation of industrial control processes if the workstation has direct access to operational technology (OT) networks. These vulnerabilities affect critical manufacturing environments globally.

## Recommendation

1. Upgrade to Redundancy Module Configuration Tool version 10.01.00 immediately to remediate CVE-2026-9633 and CVE-2026-9634.
2. Implement strict access control lists (ACLs) on system directories to ensure standard users cannot write files to locations that influence application search paths.
3. Deploy Sysmon to monitor for unexpected DLL loads from non-standard or user-writable directories.
4. Review security guidance provided by Rockwell Automation in the Trust Center.
