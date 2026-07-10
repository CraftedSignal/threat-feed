---
title: Microsoft Diagnostics Troubleshooting Wizard (MSDT) Proxy Execution Abuse
slug: 2024-01-02-msdt-proxy-execution
description: The Microsoft Diagnostics Troubleshooting Wizard (MSDT) can be abused to proxy malicious command or binary execution via malicious process arguments, potentially leading to defense evasion and arbitrary code execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - proxy-execution
  - msdt
vendors:
  - Microsoft
products:
  - Microsoft Diagnostics Troubleshooting Wizard
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2022-30190
    cvss: 7.8
    epss: 0.99374
references:
  - https://twitter.com/nao_sec/status/1530196847679401984
  - https://lolbas-project.github.io/lolbas/Binaries/Msdt/
rules:
  - title: Suspicious MSDT Execution with Rebrowse Argument
    description: Detects suspicious MSDT execution with IT_RebrowseForFile argument indicating potential abuse.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: MSDT Execution from Unusual Parent Process
    description: Detects MSDT execution initiated from suspicious parent processes like cmd.exe or powershell.exe.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft Diagnostics Troubleshooting Wizard (MSDT) is a legitimate Windows tool designed to diagnose and resolve system issues. However, attackers can abuse MSDT to execute malicious commands or binaries by manipulating its process arguments. This technique, often referred to as "living off the land," allows adversaries to bypass traditional security measures by proxying their malicious actions through a trusted system utility. This particular rule focuses on identifying instances where MSDT is used with suspicious arguments or from unusual locations. Observed exploitation has been linked to the abuse of the "Follina" vulnerability (CVE-2022-30190), although this rule is designed to detect broader MSDT abuse patterns, not just specific CVE exploitation. This technique allows attackers to evade detection by blending in with legitimate system activity and potentially gaining elevated privileges.

## Attack Chain

1.  The attacker gains initial access via an arbitrary code execution vulnerability or other means.
2.  The attacker crafts a malicious payload designed to execute commands via MSDT. This payload often involves manipulating process arguments to achieve code execution.
3.  A process such as `cmd.exe`, `powershell.exe`, or `mshta.exe` is used to launch `msdt.exe` with malicious arguments. This may include arguments like `IT_RebrowseForFile=*`, `*FromBase64*`, or arguments designed to trigger the execution of arbitrary code.
4.  `msdt.exe` is executed with the malicious arguments, effectively proxying the attacker's commands through a trusted system utility.
5.  The attacker's commands are executed within the context of `msdt.exe`, potentially allowing them to bypass security restrictions or evade detection.
6.  The attacker may use the proxied execution to download and execute additional payloads, establish persistence, or perform other malicious activities.
7.  The attacker leverages the established foothold to move laterally within the network, compromising additional systems and escalating privileges.
8.  The final objective is achieved, such as data exfiltration, ransomware deployment, or disruption of critical systems.

## Impact

Successful exploitation of MSDT proxy execution can lead to a wide range of adverse impacts, including arbitrary code execution, privilege escalation, data theft, and system compromise. The use of a trusted system utility like MSDT makes it difficult to detect and prevent these attacks, potentially allowing attackers to operate undetected for extended periods. Specific impact depends on the attacker's goals but may include widespread data loss, financial damage, and reputational harm.

## Recommendation

*   Deploy the "Suspicious Microsoft Diagnostics Wizard Execution" Sigma rule to your SIEM to detect suspicious `msdt.exe` executions.
*   Monitor process creation events for `msdt.exe` with suspicious command-line arguments, such as `IT_RebrowseForFile=*`, `*FromBase64*`, or `*/../../../*` (see Sigma rule).
*   Investigate any instances of `msdt.exe` being launched by unexpected parent processes, such as `cmd.exe`, `powershell.exe`, or `mshta.exe` (see Sigma rule).
*   Ensure that `msdt.exe` is running from a legitimate file path (`?:\\Windows\\system32\\msdt.exe` or `?:\\Windows\\SysWOW64\\msdt.exe`) and investigate any deviations.
