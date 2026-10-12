---
title: FIN7 Use of WMIC for XSL Script Execution
slug: 2026-10-xsl-script-wmic
description: The FIN7 threat group utilizes the Windows Management Instrumentation Command-line (WMIC) utility to execute arbitrary code by loading XSL files to bypass application whitelisting.
date: "2026-10-12T18:26:07Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
tags:
  - defense-evasion
  - execution
  - fin7
  - wmic
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1220
    technique_name: XSL Script Processing
    evidence: The FIN7 threat group uses the Windows Management Instrumentation Command-line (WMIC) utility to execute arbitrary code by loading remote or local XSL (eXtensible Stylesheet Language) files.
    confidence_band: high
rules:
  - title: Detect XSL Script Execution With WMIC
    description: Detects the execution of an XSL script using the WMIC process which is often indicative of malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1220
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
    - action: Deploy the Sigma detection rule to production environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides TTP-based detection logic
  hunt_leads:
    - lead: Search historic process creation logs for wmic.exe /format
      technique_id: T1220
      data_needed:
        - Process creation events with command-line parameters
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Known technique used by FIN7
---

FIN7 has been observed leveraging the Windows Management Instrumentation Command-line (WMIC) utility as a mechanism for defense evasion and arbitrary code execution. By abusing the WMIC /format switch, an attacker can specify a malicious XSL (eXtensible Stylesheet Language) file to be processed. This technique allows for the execution of scripts or system commands embedded within the stylesheet, effectively bypassing traditional application whitelisting controls that may not scrutinize script processing initiated by legitimate system binaries like wmic.exe. This activity is a known component of the FIN7 toolkit and signifies a pivot point where an attacker transitions from initial delivery to host-based code execution. Defenders must monitor process creation events for command-line arguments that combine WMIC parameters with references to .xsl files.

## Attack Chain

1. Attacker gains initial access to a target system via a secondary vector such as phishing.
2. Attacker drops a malicious XSL file onto the local disk or identifies a remote URL hosting the stylesheet.
3. Attacker executes wmic.exe with the "os get" command or similar WMI query functionality.
4. Attacker includes the "/format:" parameter pointing to the malicious XSL file path.
5. The WMIC process interprets the XSL stylesheet, triggering the execution of embedded malicious commands or scripts.
6. The system executes the payload within the context of the spawned wmic.exe or associated child processes.
7. Attacker achieves command execution to facilitate persistence, discovery, or lateral movement.

## Impact

Successful exploitation allows for arbitrary code execution, granting attackers the ability to bypass security controls, maintain persistence, and execute further stages of an intrusion. This technique has been historically linked to the FIN7 group in global criminal operations targeting financial and retail sectors, leading to significant system compromise and unauthorized data exfiltration.

## Recommendation

Deploy the provided Sigma rule to identify WMIC process executions involving XSL file loading and monitor high-risk command-line patterns.

- Deploy the Sigma rule below to your SIEM to detect command-line arguments involving WMIC and .xsl files.
- Enable Sysmon Event ID 1 (Process Creation) or Windows Event ID 4688 to capture the full command-line arguments of all executed processes.
- Audit legitimate administrative uses of WMIC /format to distinguish between benign system maintenance and malicious script execution.
- Restrict the ability of standard users to execute wmic.exe if not required for daily business operations.
