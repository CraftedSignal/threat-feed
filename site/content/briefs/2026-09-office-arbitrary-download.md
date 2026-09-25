---
title: Detection of Arbitrary File Downloads via Microsoft Office Binaries
slug: 2026-09-office-arbitrary-download
description: Adversaries may abuse legitimate Microsoft Office binaries to initiate arbitrary file downloads from remote locations, bypassing security controls by leveraging trusted processes.
date: "2026-09-25T05:20:42Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Microsoft
products:
  - Microsoft Office (Excel, Word, PowerPoint)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Abusing trusted binaries to perform downloads evades traditional network monitoring associated with common web browsers or download tools.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Winword/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Powerpnt/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Excel/
  - https://lolbas-project.github.io/lolbas/Binaries/Msoxmled/
  - https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191
rules:
  - title: Detect Potential Arbitrary File Download via Office Binary
    description: Detects when Microsoft Office binaries are invoked with command-line arguments containing HTTP or HTTPS references, indicating a potential remote download.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  hunt_leads:
    - lead: Search logs for command line arguments containing 'http' or 'https' spawned by office binaries
      technique_id: T1202
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source explicitly identifies these binaries as vectors for arbitrary download.
---

Research indicates that Microsoft Office applications can be abused to perform arbitrary file downloads from remote web servers. By exploiting unsanitized file validation routines within specific binaries, an attacker can trigger the download and execution of malicious payloads. This technique utilizes legitimate, signed binaries such as Winword.exe, Excel.exe, Powerpnt.exe, and Msoxmled.exe to initiate network requests to attacker-controlled infrastructure. These binaries are often trusted by security software, making them ideal candidates for living-off-the-land (LotL) attacks. Defenders should monitor for instances where these Office processes spawn network connections or execute command-line arguments containing HTTP or HTTPS URIs, as this behavior is typically indicative of malicious activity rather than standard document editing workflows.

## Impact

Successful exploitation allows attackers to pull secondary malicious payloads onto a target system, facilitating initial access, persistence, or data exfiltration. This technique has been observed in various contexts to bypass perimeter defenses by using trusted Microsoft-signed binaries to conduct malicious network communication.

## Recommendation

Prioritize the deployment of the provided Sigma rule to monitor for suspicious command-line patterns originating from Office applications.

- Enable process creation logging (Event ID 1) via Sysmon or Windows Security logs to capture command-line arguments.
- Implement monitoring for child processes spawned by Office applications that initiate network connections.
- Baseline expected behavior for internal Office applications to identify and filter out legitimate update or cloud-sync activities.
