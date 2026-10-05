---
title: Detection of Renamed Living off the Land Binaries
slug: 2026-10-windows-lolbas-renamed
description: This detection targets threat actors attempting to evade security defenses by renaming native Windows binaries to circumvent signature-based detection or security policy enforcement.
date: "2026-10-05T12:24:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
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
    technique_id: T1036
    technique_name: Masquerading
    evidence: The following analytic identifies a LOLBAS process being executed where it's process name does not match it's original file name attribute.
    confidence_band: high
rules:
  - title: Detect Renamed Windows LOLBAS Execution
    description: Detects execution of a Windows native binary where the process name does not match the original file name attribute, indicating potential masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1036.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy process rename detection logic
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic mapping
  mitigation_plan:
    - priority: medium_term
      action: Review and allowlist authorized vendor applications that perform renaming
      owner: IT Operations
      evidence: Known false positive documentation
---

Adversaries frequently employ masquerading techniques to bypass security controls by renaming legitimate Windows binaries (Living Off the Land Binaries, or LOLBAS) to mimic benign system files or other applications. This technique allows threat actors to execute malicious code or perform unauthorized tasks using trusted, signed utilities while evading signature-based detections or policy-driven enforcement.

The detection logic focuses on the mismatch between the process name attribute and the original file name metadata. By analyzing process execution events from EDR telemetry, defenders can identify instances where a known LOLBAS tool - as defined by the LOLBAS project - is executing under an alias. This behavioral indicator is highly relevant for detecting defense evasion, as it often precedes lateral movement, credential access, or data exfiltration stages. Security teams should prioritize tuning to account for legitimate vendor-specific software that may copy or rename system binaries for internal application compatibility.

## Impact

Successful execution of renamed LOLBAS binaries can lead to unauthorized code execution, persistence, and privilege escalation within the environment. Because these binaries are digitally signed by Microsoft, they are often overlooked by traditional security tools, increasing the risk of stealthy, long-term compromises that bypass standard host-based protections.

## Recommendation

* Deploy the provided Sigma rule to identify process name mismatches for known LOLBAS binaries.
* Enable Sysmon Event ID 1 or Windows Event Log Security 4688 to ensure the capture of process name, original file name, and command-line execution telemetry.
* Use the Common Information Model (CIM) to map process execution data to the Endpoint data model to ensure detection consistency.
* Tune the detection rule to account for authorized MSI installers and known vendor application behavior that legitimately uses renamed system binaries to reduce false positives.
