---
title: Braodo Stealer Browser Process Termination TTP
slug: 2026-10-braodo-browser-killer
description: The Braodo stealer and similar infostealer families utilize taskkill to terminate browser processes to unlock sensitive credential and session data files for exfiltration.
date: "2026-10-19T02:51:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - infostealer
  - credential-theft
  - defense-evasion
affected_os:
  - Windows
rules:
  - title: Detect Malicious Taskkill Usage Targeting Browsers
    description: Detects the use of taskkill to terminate common browser processes, a technique used by stealers like Braodo to access locked credential files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
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
    - action: Deploy the Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: Required for proactive detection of stealer TTPs.
  hunt_leads:
    - lead: Search historical logs for taskkill commands targeting browser processes.
      technique_id: T1685
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Historical TTP analysis.
---

The Braodo stealer and various other infostealer malware families, including those associated with Scattered Lapsus$ Hunters, Hellcat, and Castle RAT, employ a common technique to facilitate credential theft. By utilizing the legitimate Windows utility 'taskkill', malware actors forcefully terminate active browser processes such as Chrome, Edge, Firefox, Brave, and Opera. This action is performed to bypass file locking mechanisms, allowing the malware to access and exfiltrate sensitive files containing stored passwords, cookies, and login information. While taskkill is a standard system tool, its invocation by unauthorized processes targeting browser applications is a high-fidelity indicator of malicious intent. Monitoring for this pattern is critical for identifying active infostealer infections before significant data exfiltration occurs.

## Attack Chain

1. Malware gains initial execution on the victim host through a secondary delivery vector.
2. The malicious binary performs environment discovery to identify installed browsers.
3. The malware executes 'taskkill.exe' with arguments targeting specific browser process names (e.g., /F /IM chrome.exe).
4. Active browser processes are forcefully terminated, releasing file locks on browser-based data stores.
5. The malware accesses local files, specifically those containing encrypted passwords and session cookies (e.g., Login Data, Cookies).
6. Stolen data is packaged into a temporary staging file or directory.
7. The collected data is exfiltrated to attacker-controlled C2 infrastructure.

## Impact

Successful execution of this technique typically leads to the compromise of user credentials, personal identifiable information (PII), and session tokens. These attacks primarily target endpoints in sectors where users maintain active browser sessions, facilitating account takeovers and secondary unauthorized access. Multiple stealer families, including Braodo, Vidar, and Phantom, utilize this method, potentially resulting in widespread credential theft across large organizations.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious process termination events involving browser binaries.
* Enable Sysmon Event ID 1 (Process Creation) across all Windows endpoints to capture command-line arguments.
* Tune the detection to exclude legitimate IT management software or automated maintenance scripts that may periodically restart browser applications.
* Investigate the parent process of any 'taskkill.exe' command lines targeting browsers to identify the source of the malicious activity.
