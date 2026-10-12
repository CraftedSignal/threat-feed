---
title: Abuse of Windows Attrib.exe to Hide Malicious Files
slug: 2026-10-hiding-files-attrib-exe
description: Attackers abuse the Windows attrib.exe binary with the +h flag to conceal malicious files and directories from users and security software as part of a defense evasion strategy.
date: "2026-10-12T17:46:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - file-hiding
  - persistence
  - windows
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
    evidence: The following analytic detects the use of the Windows binary attrib.exe to hide files or directories by marking them with specific flags.
    confidence_band: high
rules:
  - title: Detect Hiding Files and Directories with Attrib.exe
    description: Detects the use of attrib.exe to mark files or directories as hidden using the +h flag.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search historical EDR logs for attrib.exe executions containing +h flags.
      technique_id: T1222.001
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: This activity is significant because hiding files can be a tactic used by attackers.
  mitigation_plan:
    - priority: medium_term
      action: Restrict user permissions to execute non-essential administrative utilities via AppLocker or WDAC.
      owner: IT Operations
      addresses: T1222.001
---

The Windows binary attrib.exe is a legitimate system utility used to display or change file attributes. Threat actors frequently abuse this tool to perform defense evasion by marking malicious files, tools, or persistence mechanisms with the hidden (+h) attribute. This technique renders files invisible to standard Windows Explorer views and may bypass basic security inspection that does not account for hidden directory content. This behavior has been associated with various malicious activities, including the deployment of information stealers (such as Azorult and crypto stealers), keyloggers, and the use of malicious installers like Inno Setup loaders. Defenders monitoring endpoint process creation should focus on the use of attrib.exe with the +h argument, as this is rarely necessary for standard administrative tasks in many environments.

## Impact

Successful execution of this technique allows attackers to persist in the environment undetected by hiding secondary payloads and post-exploitation tools. This contributes to long-term dwelling and complicates incident response efforts by obscuring evidence on the infected host.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious process execution of attrib.exe with the hidden attribute flag. Ensure that EDR telemetry, specifically process command-line arguments and parent process information, is being ingested and normalized to the Endpoint data model to support this detection.
