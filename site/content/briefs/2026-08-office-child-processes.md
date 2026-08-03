---
title: Suspicious Microsoft Office Child Process Activity
slug: 2026-08-office-child-processes
description: Microsoft Office applications are frequently abused to spawn system processes to execute malicious code, download payloads, or facilitate privilege escalation.
date: "2026-08-03T08:54:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_20h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h1:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_20h2:*:*:*:*:*:*:*:*
vendors:
  - Microsoft
products:
  - Microsoft Office
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Detects a suspicious process spawning from one of the Microsoft Office suite products.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: The rule monitors wmic.exe as a spawned child process.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The rule monitors rundll32.exe and regsvr32.exe as spawned child processes.
    confidence_band: high
cves:
  - id: CVE-2022-30190
    cvss: 7.8
    epss: 0.99374
rules:
  - title: Detect Suspicious Microsoft Office Child Processes
    description: Detects a suspicious process spawning from one of the Microsoft Office suite products (Word, Excel, PowerPoint, etc.)
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for Office process lineage
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify historical instances of WINWORD.EXE or EXCEL.EXE spawning system binaries
      technique_id: T1204.002
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
---

Microsoft Office suite applications (Word, Excel, PowerPoint, etc.) are common vectors for initial access and execution. Attackers exploit these applications via malicious documents containing macros, DDE, or embedded vulnerabilities (such as Follina, CVE-2022-30190) to force the host application to spawn child processes. These spawned processes are frequently used to execute secondary stages of an attack, such as downloading further malware, establishing persistence, or executing administrative commands. Because legitimate Office activity rarely involves launching system binaries like PowerShell, cmd, or rundll32, monitoring these parent-child relationships is a critical control for detection engineering teams. Defenders should focus on identifying atypical process lineage where Office applications act as the parent for system tools or binaries located in suspicious writeable directories.

## Attack Chain

1. Victim opens a weaponized Microsoft Office document via email or download.
2. The document executes embedded malicious code (Macro, OLE object, or exploit).
3. The Office application invokes a system utility (e.g., cmd.exe or powershell.exe) to bypass security controls.
4. The spawned child process executes encoded scripts or downloads external payloads.
5. The attacker gains initial execution and proceeds to execute secondary modules.
6. Persistence mechanisms are established via scheduled tasks or registry modifications.
7. Final objective (e.g., ransomware deployment or credential theft) is achieved.

## Impact

Successful exploitation of this vector allows adversaries to gain initial access, execute code under the context of the user, move laterally, and deploy ransomware or information-stealing malware within an enterprise environment.

## Recommendation

* Deploy the provided Sigma rule to alert on suspicious process spawning from Microsoft Office applications.
* Monitor for process creation events (Event ID 1) where the ParentImage matches the Microsoft Office suite.
* Investigate instances where Office processes spawn tools like PowerShell, CMD, WScript, or MSHTA, particularly if they are originating from non-standard paths like \AppData\ or \Windows\Temp\.
