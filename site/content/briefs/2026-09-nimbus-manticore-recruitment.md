---
title: Nimbus Manticore Targets Developers with Node.js-based Cross-Platform RATs
slug: 2026-09-nimbus-manticore-recruitment
description: The Iranian threat actor Nimbus Manticore is distributing NodeRabbit and PollCat cross-platform RATs via trojanized coding challenges on LinkedIn to compromise developer systems.
date: "2026-09-01T14:10:08Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Nimbus Manticore
tags:
  - espionage
  - rat
  - phishing
  - recruitment
  - cross-platform
vendors:
  - Microsoft
products:
  - VS Code
  - Outlook
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Its operators deliver [NodeRabbit] through spear-phishing messages on LinkedIn and other job search platforms that contain trojanized coding challenge archives.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: 'Persistence is achieved depending on the operating system: a Windows Run registry key on Windows, a cron entry for Linux, and a launch agent on macOS.'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: PollCat also searches for folders matching 24 hard-coded strings corresponding to software and security vendors.
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/iranian-hackers-pose-as-recruiters-to.html
iocs:
  - type: domain
    value: plugplay.azurewebsites.net
  - type: domain
    value: rgbteller.azurewebsites.net
  - type: domain
    value: wslwebui.azurewebsites.net
ioc_counts:
  domain: 3
rules:
  - title: Detect Suspicious Node.js Persistence via NPM Package Import
    description: Detects execution of Node.js applications that load malicious npm packages from local project subdirectories, consistent with NodeRabbit and PollCat delivery.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block listed C2 domains
      owner: SOC
      due: 24h
      evidence: Source explicitly lists three Azure C2 domains
  hunt_leads:
    - lead: Search for existence of 'node_modules/.cache/' directories with subdirectories of randomized hex names
      technique_id: T1059.007
      data_needed:
        - Filesystem telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Malware launches from node_modules/.cache/.<random>/index.js
---

The Iranian threat actor Nimbus Manticore (also known as Iranian Dream Job) has expanded its arsenal with two new Node.js-based remote access trojans (RATs), NodeRabbit and PollCat. These tools are delivered via spear-phishing campaigns on platforms like LinkedIn, where attackers pose as recruiters. Victims are lured into downloading trojanized coding challenge archives containing a project management application. Malicious code is embedded within the project's 'server.js' file, which imports a trojanized npm package ('colorized_terminal' or 'pretty-log') to silently launch an implant. These RATs are cross-platform, affecting Windows, Linux, and macOS, and are used for cyber espionage. The group has historically used C, C++, and Go, but the shift to Node.js indicates an effort to blend into developer environments and simplify cross-platform deployment.

## Attack Chain

1. Attacker establishes contact with a software engineer on LinkedIn, posing as a talent acquisition specialist.
2. Victim downloads a ZIP archive (e.g., 'Front-Technical-Challenge.zip') containing a project management tool.
3. Victim runs the 'server.js' component, which triggers the import of a trojanized npm package ('colorized_terminal' or 'pretty-log').
4. The malicious package executes an index.js file from 'node_modules/.cache/' as a detached background process.
5. The NodeRabbit/PollCat implant establishes C2 communication with Azure-hosted infrastructure via hardcoded API endpoints.
6. Malware ensures persistence using OS-specific methods (Windows Registry Run keys, Linux cron jobs, or macOS launch agents).
7. Attacker executes commands to harvest system data, steal browser/Outlook credentials, or inject persistence mechanisms into local Git repositories.

## Impact

The campaign targets software engineers in critical sectors across the Middle East and Africa. Successful exploitation allows for complete remote control of the host, enabling data exfiltration, credential harvesting (including Outlook OST/PST files), and deep reconnaissance of the victim's development environment.

## Recommendation

1. Block the C2 domains listed in the IOC table at the DNS resolver level to disrupt command-and-control communications.
2. Implement detection logic to monitor for unexpected npm package imports from non-registry locations or obscure paths within project 'node_modules' directories.
3. Prohibit the execution of untrusted coding challenges on systems with access to production environments or sensitive source code.
4. Hunt for the presence of the identified malicious npm package names ('colorized_terminal' v2.1.0, 'pretty-log' v2.1.0) in local node_modules folders.
