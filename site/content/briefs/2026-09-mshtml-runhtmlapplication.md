---
title: Suspicious Execution via Mshtml.dll RunHTMLApplication
slug: 2026-09-mshtml-runhtmlapplication
description: Attackers use the mshtml.dll RunHTMLApplication export via rundll32.exe to execute arbitrary code through various protocol handlers.
date: "2026-09-01T12:23:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - execution
  - evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Detects execution of commands that leverage the mshtml.dll RunHTMLApplication export to run arbitrary code.
    confidence_band: high
references:
  - https://twitter.com/n1nj4sec/status/1421190238081277959
  - https://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_TROJAN.WIN32.POWESSERE.G_MITIGATION_BYPASS_PART2.txt
rules:
  - title: Detect Suspicious Mshtml.dll RunHTMLApplication Usage
    description: Detects execution of commands that leverage the mshtml.dll RunHTMLApplication export to run arbitrary code via protocol handlers.
    platform: sigma
    severity: high
    tactics:
      - execution
      - stealth
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify potential mshtml.dll abuse.
      owner: Detection Engineering
      due: 48h
      evidence: Rule targets high-signal process creation behavior.
  hunt_leads:
    - lead: Search for rundll32.exe executions containing the strings 'mshtml' and 'RunHTMLApplication'.
      technique_id: T1218.011
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies this as suspicious behavior.
---

This threat involves the abuse of the mshtml.dll library on Windows systems, specifically leveraging the RunHTMLApplication export. By invoking this export through rundll32.exe, attackers can bypass security controls and execute arbitrary scripts or code embedded in remote or local HTML files. This technique supports multiple protocol handlers, including vbscript, javascript, file, and http, allowing for versatile payload delivery. Defenders should monitor for command-line arguments that reference mshtml and the RunHTMLApplication export, as these are rarely used in legitimate administrative or application activity. This method has been documented as a technique for security product evasion and malware execution, often serving as an initial access or persistence mechanism.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the user running the command, potentially leading to system compromise, data exfiltration, or deployment of secondary malware. While not linked to a specific campaign, the technique is a known mechanism for bypassing traditional signature-based detections and security product mitigations.

## Recommendation

Deploy the provided Sigma rule to identify command-line activity indicative of this technique. Enable command-line logging (Sysmon Event ID 1 or Windows Event ID 4688) across the environment to capture full execution paths and command arguments. Monitor for suspicious parent processes attempting to spawn rundll32.exe with these specific command-line arguments.
