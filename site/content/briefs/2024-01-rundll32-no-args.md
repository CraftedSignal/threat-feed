---
brief_id: brief-2024-01-03-rundll32-no-args
event_id: brief-2024-01-03-rundll32-no-args
revision: 2
activity_at: "2026-11-20T03:11:01Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:6205e414f6555e97982df4d269f511f8b5d7c33fa25bc8c939a5eff6c77b0016
    summary: exploited:true; KEV CVE-2021-34527
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Suspicious Rundll32 Execution Without Command-Line Arguments
slug: 2024-01-rundll32-no-args
description: The execution of rundll32.exe without command-line arguments is detected via endpoint telemetry, a behavior indicative of potential malicious activity such as Cobalt Strike, leading to arbitrary code execution and system compromise.
date: "2024-01-03T17:23:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2021-11-03T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_20h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_20h2:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-M8SEC-CVE-2021-34527&utm_source=rss&utm_medium=rss
tags:
  - defense-evasion
  - windows
  - rundll32
vendors:
  - Microsoft
products:
  - Windows Print Spooler
affected_os:
  - Windows 10 1507
  - Windows 10 1607
  - Windows 10 1809
  - Windows 10 1909
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.011
    subtechnique_name: Rundll32
cves:
  - id: CVE-2021-34527
    cvss: 8.8
    epss: 0.99792
    kev: true
    kev_status: "true"
references:
  - https://attack.mitre.org/techniques/T1218/011/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md
  - https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
  - https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-M8SEC-CVE-2021-34527&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Suspicious Rundll32 Execution Without Command-Line Arguments
    description: Detects the execution of rundll32.exe without any command-line arguments, which is often associated with malicious activities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Rundll32 Execution With Empty Command Line
    description: Detects the execution of rundll32.exe with an empty string as command line, which is often associated with malicious activities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-09-16T02:41:24Z"
    level: L2
    summary: poc_available; added CVE-2021-34527; OS windows 10 1507; OS windows 10 1607; OS windows 10 1809; OS windows 10 1909
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-M8SEC-CVE-2021-34527&utm_source=rss&utm_medium=rss
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2021-34527
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The use of rundll32.exe is a common Windows feature, but its execution without any command-line arguments is highly unusual and often associated with malicious activities. This behavior is monitored using endpoint detection and response (EDR) systems. Attackers frequently leverage rundll32 to execute arbitrary code, bypass security controls, or perform reconnaissance. Its misuse is often tied to exploitation frameworks and post-exploitation activity. The absence of command-line arguments in rundll32 execution significantly raises suspicion, suggesting attempts to conceal malicious actions or leverage default rundll32 behaviors for nefarious purposes. This detection is crucial for identifying potential compromises and preventing further escalation of attacks. This behavior can also be related to CVE-2021-34527 PrintNightmare vulnerability.

## Attack Chain

1. An attacker gains initial access to a system, possibly through exploiting a vulnerability (like CVE-2021-34527), or social engineering.
2. The attacker deploys or has access to a malicious payload on the compromised system.
3. The attacker attempts to execute code using `rundll32.exe` without any command-line arguments. This could be achieved via another process or script.
4. `rundll32.exe` starts without any parameters, indicating an attempt to leverage its default behavior maliciously.
5. The attacker uses this initial access to perform privilege escalation or lateral movement activities.
6. The attacker executes further malicious commands, loads additional payloads, or dumps credentials from the system.
7. The attacker establishes persistence on the system to maintain unauthorized access.
8. The final objective includes data exfiltration, ransomware deployment, or other malicious activities.

## Impact

The successful exploitation of this technique can lead to arbitrary code execution, potentially granting attackers full control over the compromised system. This could result in the theft of sensitive data, the deployment of ransomware, or the disruption of critical services. Due to the wide usage of Windows, many systems are vulnerable. Historically, attacks leveraging rundll32 have resulted in significant financial losses and reputational damage for affected organizations.

## Recommendation

*   Enable Sysmon process creation logging to capture `rundll32.exe` executions, as indicated by the `data_source` field.
*   Deploy the Sigma rule `Detect Suspicious Rundll32 Execution Without Command-Line Arguments` to detect the specific malicious behavior described in this brief.
*   Investigate any instance of `rundll32.exe` execution without command-line arguments to determine if it is legitimate or malicious.
*   Review and patch systems for CVE-2021-34527 to prevent exploitation related to PrintNightmare, as listed in the `cve` tag.
*   Monitor process execution logs for parent-child relationships to identify the process that initiated the suspicious `rundll32.exe` execution.
