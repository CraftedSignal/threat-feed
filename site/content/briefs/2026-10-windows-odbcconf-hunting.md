---
title: Abuse of Odbcconf.exe for Living off the Land Attacks
slug: 2026-10-windows-odbcconf-hunting
description: Attackers frequently abuse the legitimate, signed Windows utility Odbcconf.exe to execute arbitrary code or load malicious DLLs, facilitating defense evasion and persistence.
date: "2026-10-12T18:17:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - living-off-the-land
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Odbcconf.exe can be used by attackers to execute arbitrary commands or load malicious DLLs, potentially leading to code execution or persistence.
    confidence_band: high
references:
  - https://strontic.github.io/xcyclopedia/library/odbcconf.exe-07FBA12552331355C103999806627314.html
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1218.008/T1218.008.yaml
rules:
  - title: Detect Odbcconf.exe Execution
    description: Detects the execution of odbcconf.exe which is often used by attackers for LOLBin activity to load arbitrary DLLs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.008
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Odbcconf process creation detection rule.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic content for windows_odbcconf_hunting.yml
  mitigation_plan:
    - priority: medium_term
      action: Implement strict application control and execution policy (AppLocker or WDAC) to restrict execution of non-standard binaries.
      owner: IT Operations
      addresses: T1218.008
      evidence: General best practices for mitigating LotL techniques
---

Odbcconf.exe is a legitimate, signed Microsoft Windows utility designed to configure ODBC drivers and data sources. Adversaries leverage this binary as a Living off the Land (LotL) technique to bypass security controls and execute malicious payloads. By using command-line arguments to load external DLLs or register components, attackers can achieve arbitrary code execution, escalate privileges, or maintain long-term persistence within an environment. Because the utility is natively present on Windows systems, its execution is often overlooked by standard perimeter defenses. This brief provides guidance for security operations teams to monitor and investigate process creation events related to Odbcconf.exe to identify potentially unauthorized system activity.

## Attack Chain

1. Attacker establishes initial access via secondary means (e.g., phishing, exploit).
2. Attacker downloads or stages a malicious DLL to a directory on the target system.
3. Attacker identifies Odbcconf.exe on the target host as an execution proxy.
4. Attacker executes Odbcconf.exe using command-line arguments (e.g., /S /A {action} /F {file}) to target the malicious DLL.
5. Odbcconf.exe loads the unauthorized DLL during its operation.
6. Malicious code within the DLL executes in the context of the Odbcconf.exe process.
7. Attacker achieves persistence or further system compromise.

## Impact

Successful abuse of Odbcconf.exe enables attackers to operate stealthily, as the execution appears to originate from a trusted, signed Microsoft binary. This can result in unauthorized code execution, bypass of application control policies, lateral movement, or the establishment of persistent backdoors, ultimately leading to sensitive data exfiltration or system takeover.

## Recommendation

Prioritize the identification of suspicious Odbcconf.exe execution patterns to filter out legitimate administrative activity.
- Deploy the Sigma rule provided below to your SIEM and tune it to baseline standard administrative behavior in your environment.
- Enable Sysmon Event ID 1 or Windows Security Event ID 4688 to capture comprehensive command-line arguments for all process execution.
- Map captured process telemetry to the Endpoint data model (CIM) to enable behavioral analysis and anomaly detection.
- Investigate any Odbcconf.exe execution where the parent process is unexpected (e.g., non-standard administrative tools) or where the command line references suspicious directories or DLL files.
