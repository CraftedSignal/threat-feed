---
title: Mirage Kitten APT Deploys NodeRabbit and PollCat Backdoors via Trojanized Coding Challenges
slug: 2026-09-mirage-kitten-noderabbit
description: The Mirage Kitten threat actor is targeting aviation and FinTech software engineers with spear-phishing campaigns distributing trojanized coding challenge archives containing cross-platform Node.js and JavaScript backdoors.
date: "2026-09-01T11:56:59Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Mirage Kitten
tags:
  - phishing
  - malware
  - rat
  - developer-targeting
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The infection chain begins with fake recruiter accounts contacting prospective targets on a job search platform.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: creates HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeUpdate registry key
    confidence_band: high
references:
  - https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/
iocs:
  - type: hash_md5
    value: 1ea83e4e4592b01e4acab63eb867bee5
  - type: url
    value: https://plugplay.azurewebsites.net
  - type: url
    value: https://rgbteller.azurewebsites.net
  - type: url
    value: https://wslwebui.azurewebsites.net
ioc_counts:
  hash_md5: 1
  url: 3
rules:
  - title: Detect NodeRabbit RAT Persistence via Registry Modification
    description: Detects NodeRabbit persistence on Windows where the malware copies itself to the EdgeUpdate folder and modifies the Run registry key
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block listed C2 domains on all enterprise egress points
      owner: SOC
      due: 1h
      evidence: NodeRabbit C2 infrastructure list
  hunt_leads:
    - lead: Search for files created in %APPDATA%\Microsoft\EdgeUpdate\msedge_update.js
      technique_id: T1547.001
      data_needed:
        - File system logging (Sysmon Event ID 11)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Persistence mechanism for Windows
  mitigation_plan:
    - priority: immediate
      action: Strictly enforce code review and dependency vetting for all engineering personnel
      owner: IT Operations
      addresses: Trojanized coding challenge vectors
      evidence: README file analysis
---

The Mirage Kitten APT group has launched a new campaign targeting software engineers within the aviation and FinTech sectors. The campaign utilizes a sophisticated delivery mechanism involving fake recruiter outreach on professional networking platforms like LinkedIn. Victims are invited to complete technical coding assessments, which are hosted on Amazon S3 buckets. These archives contain trojanized software development projects - specifically an application named TaskFlow - that include malicious npm packages such as 'colorized_terminal' (v2.1.0) and 'pretty-log' (v2.1.0).

Once executed, these packages trigger the installation of 'NodeRabbit', a previously undocumented, cross-platform remote access trojan (RAT) written in Node.js. NodeRabbit is capable of executing arbitrary shell commands, performing system reconnaissance, and establishing persistent backdoors on Windows, Linux, and macOS systems. During the same investigation, researchers identified a secondary RAT named 'PollCat', written in obfuscated JavaScript. This represents a significant shift in the group's tradecraft from native C/C++ or Go malware to high-level language-based implants, likely intended to blend into developer environments.

## Attack Chain

1. Mirage Kitten operators perform reconnaissance and reach out to targets on job search platforms posing as recruiters.
2. The target receives a link to a project archive (e.g., Front-Technical-Challenge.zip) hosted on Amazon S3.
3. The victim downloads and extracts the archive, which includes a malicious npm package dependency in the `node_modules` directory.
4. Upon running the development project, the malicious package executes an implant from `node_modules/.cache/.320697f1/index.js` as a background process.
5. The implant (NodeRabbit) generates a unique agent ID based on host system metadata and attempts to bind to a local TCP port to ensure single-instance operation.
6. Persistence is established: via Windows Registry `Run` keys for `nodew.exe`, cron jobs on Linux, or LaunchAgents on macOS.
7. The malware initiates beaconing to Azure-hosted C2 infrastructure using AES-256-GCM encrypted JSON payloads.
8. The final objective is achieved via arbitrary command execution and exfiltration of system information or developer assets.

## Impact

The campaign targets high-value individuals within the aviation and FinTech sectors, posing a significant risk of intellectual property theft, unauthorized access to secure development environments, and potential follow-on compromise of critical corporate infrastructure. The usage of job search lures exploits the trust relationship inherent in the hiring process, making it difficult for standard email filters to flag the activity.

## Recommendation

1. Deploy the Sigma rules below to monitor for suspicious process execution patterns related to Node.js implants.
2. Block outbound connections to the identified Azure-hosted C2 infrastructure at the network perimeter.
3. Implement strict controls on the execution of developer environments; verify the integrity of `node_modules` and external project dependencies before execution.
4. Hunt for the presence of the identified malicious file paths and registry modifications on developer workstations.
