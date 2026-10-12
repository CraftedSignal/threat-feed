---
title: Detection of Malicious mshta.exe Inline Protocol Execution
slug: 2026-10-mshta-inline-execution
description: Attackers abuse the legitimate Windows mshta.exe utility to execute malicious scripts via inline protocol handlers to bypass security controls and achieve code execution.
date: "2026-10-12T17:39:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - lotl
  - mshta
  - windows
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
    evidence: The following analytic detects the execution of mshta.exe with inline protocol handlers such as JavaScript, VBScript, and About.
    confidence_band: high
rules:
  - title: Detect mshta.exe Inline HTA Execution
    description: Detects execution of mshta.exe with inline protocol handlers such as JavaScript, VBScript, or About, which is often used for malicious script execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for mshta abuse.
      owner: Detection Engineering
      due: 24h
      evidence: Analytic identification of mshta abuse.
  hunt_leads:
    - lead: Search for instances of mshta.exe spawning with protocol handlers in existing EDR logs.
      technique_id: T1218.005
      data_needed:
        - Process creation logs with command-line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this as a high-value detection technique.
  mitigation_plan:
    - priority: short_term
      action: Enable full command-line logging on all Windows endpoints.
      owner: IT Operations
      addresses: T1218.005
      evidence: Detection requires full command-line visibility.
---

The Microsoft HTML Application (MSHTA) utility is a legitimate Windows component designed to execute .hta files. However, it is frequently abused by threat actors as a Living off the Land (LotL) technique to execute malicious code. By invoking mshta.exe with inline protocol handlers such as JavaScript, VBScript, or 'about:', attackers can execute arbitrary code directly from the command line or via downloaded scripts without dropping files on disk. This activity is a common vector for deploying various malware strains, including Gozi, XWorm, and stealer-type payloads, to facilitate privilege escalation, persistence, or data exfiltration. Defenders must monitor process execution telemetry for command-line arguments that utilize these protocol handlers to identify and interrupt unauthorized script execution.

## Impact

Successful exploitation of this technique allows attackers to evade signature-based endpoint security, execute malicious code within the context of a trusted Windows process, and establish persistence. This technique has been observed in campaigns involving various malware families, including Gozi, XWorm, Rustonotto, and BlankGrabber. Failure to detect this activity can lead to full system compromise and significant data loss within an enterprise environment.

## Recommendation

Prioritize the identification of mshta.exe execution patterns in EDR telemetry to detect unauthorized script execution.

- Deploy the provided Sigma rule to your SIEM/EDR platform to alert on suspicious command-line patterns.
- Enable Sysmon (Event ID 1) or Windows Security Log (Event ID 4688) on all Windows endpoints to ensure process creation logging includes full command-line arguments.
- Use the Splunk Common Information Model (CIM) to normalize process data to ensure detection coverage across the environment.
- Investigate any mshta.exe processes spawning from suspicious parent processes or containing unusual inline command arguments.
