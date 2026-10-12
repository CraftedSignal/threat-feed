---
title: Abuse of Microsoft HTML Help via InfoTech Storage Handlers
slug: 2026-10-html-help-abuse
description: Attackers abuse the Microsoft HTML Help utility (hh.exe) to execute arbitrary code or scripts by loading malicious Compiled HTML Help (CHM) files via InfoTech Storage Handlers.
date: "2026-10-12T17:39:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - HTML Help
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The following analytic detects the execution of hh.exe (HTML Help) using InfoTech Storage Handlers to load Windows script code from a Compiled HTML Help (CHM) file.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1218/001/
  - https://lolbas-project.github.io/lolbas/Binaries/Hh/
rules:
  - title: Detect HTML Help Using InfoTech Storage Handlers
    description: 'Detects the execution of hh.exe using InfoTech Storage Handlers (its: or mk:@MSITStore:) to load CHM files, which is a known method for executing arbitrary code.'
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.001
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
    - action: Deploy Sigma detection rule to SIEM/EDR environment.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for hh.exe abuse.
  hunt_leads:
    - lead: Search for hh.exe execution with 'its:' or 'mk:@MSITStore:' in command lines.
      technique_id: T1218.001
      data_needed:
        - process_creation_logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Technique relies on specific command line patterns.
  mitigation_plan:
    - priority: medium
      action: Monitor and restrict usage of .chm files via GPO or application control if not required for business.
      owner: IT Operations
      addresses: T1218.001
      evidence: Standard defensive hardening for LotL binaries.
---

The Microsoft HTML Help utility, hh.exe, is a legitimate binary intended to display help files in the Compiled HTML Help (CHM) format. Threat actors frequently abuse this utility as a "Living off the Land" (LotL) technique to execute arbitrary code or scripts embedded within malicious CHM files. By leveraging the InfoTech Storage (its:) or MSITStore handlers, an attacker can force hh.exe to load a remote or locally stored CHM file containing malicious content. This technique is often used to bypass traditional security controls that monitor for more common executable formats. If successful, this activity can facilitate initial access, persistence, or privilege escalation within a Windows environment. Detection of this activity requires monitoring command-line arguments for specific handlers associated with HTML Help.

## Attack Chain

1. Attacker crafts a malicious CHM file containing obfuscated script code or embedded payloads.
2. Attacker delivers the CHM file to the victim system via email attachment, direct download, or a link.
3. Victim or automated process triggers the execution of hh.exe.
4. The command-line utilizes the 'its:' or 'mk:@MSITStore:' protocol handler to reference the malicious CHM file.
5. The hh.exe process interprets the handler and initiates the loading of the embedded script or payload.
6. The script code executes within the context of the hh.exe process, potentially leading to further compromise.
7. Attacker achieves persistence, privilege escalation, or exfiltration based on the payload's intent.

## Impact

Successful abuse of HTML Help allows for the execution of arbitrary code, enabling attackers to maintain persistence, escalate privileges, or execute secondary payloads. This technique has been observed in various campaigns, including those attributed to groups like APT37, to facilitate the execution of malware such as FadeStealer or Rustonotto.

## Recommendation

Prioritize the identification of suspicious hh.exe execution patterns in endpoint telemetry.
- Deploy the Sigma rule provided in this brief to detect instances of hh.exe using InfoTech Storage Handlers.
- Enable Sysmon or equivalent EDR process-creation logging to capture command-line arguments, specifically looking for the 'its:' and 'mk:@MSITStore:' strings.
- Audit the use of CHM files in the environment, particularly those originating from untrusted external sources.
