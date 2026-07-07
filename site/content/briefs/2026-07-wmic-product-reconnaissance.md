---
title: WMIC Product Reconnaissance for Defense Evasion
slug: 2026-07-wmic-product-reconnaissance
description: A threat brief details the use of `wmic.exe` by attackers to perform product reconnaissance, specifically to identify installed firewall and antivirus software, facilitating defense evasion and tailored attack execution.
date: "2026-07-03T14:50:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - defense-evasion
  - windows
  - wmic
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: Detects the execution of WMIC in order to get a list of firewall and antivirus products
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Detects the execution of WMIC in order to get a list of firewall and antivirus products
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_recon_product.yml
  - https://thedfirreport.com/2023/03/06/2022-year-in-review/
  - https://www.yeahhub.com/list-installed-programs-version-path-windows/
  - https://learn.microsoft.com/en-us/answers/questions/253555/software-list-inventory-wmic-product
rules:
  - title: Potential Product Reconnaissance Via Wmic.EXE
    description: Detects the execution of WMIC in order to get a list of firewall and antivirus products or other installed software, indicating reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1047
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This brief describes a common post-compromise reconnaissance technique where attackers leverage the legitimate Windows Management Instrumentation Command-line (WMIC) utility, specifically `wmic.exe`, to gather information about the software installed on a compromised system. Observed in various adversarial campaigns, including those outlined in The DFIR Report's 2022 year-in-review, this technique focuses on identifying security products such as firewalls and antivirus solutions. By understanding the defensive posture of the target system, threat actors can adapt their tactics, techniques, and procedures (TTPs) to evade detection, disable security controls, or exploit known vulnerabilities in specific applications. Detecting this activity early is critical for defenders to prevent further progression of an attack.

## Attack Chain

[The provided intelligence describes a single technique (WMIC reconnaissance) rather than a full, multi-stage attack chain from initial access to impact. Therefore, a detailed attack chain cannot be constructed for this brief.]

## Impact

Successful product reconnaissance provides attackers with critical intelligence to escalate privileges, evade defenses, and move laterally within a network. By knowing the specific security tools or applications present, adversaries can develop targeted exploits, bypass detection mechanisms, or uninstall/disable security software, significantly increasing the likelihood of successful data exfiltration, ransomware deployment, or long-term persistence without immediate detection.

## Recommendation

*   Deploy the "Potential Product Reconnaissance Via Wmic.EXE" Sigma rule to your SIEM.
*   Enable Sysmon process-creation logging on all Windows endpoints to ensure the necessary telemetry for the above rule is collected.
*   Investigate alerts from the Sigma rule for signs of further adversarial activity or follow-on actions indicative of defense evasion.
