---
title: Lazarus Group's Brandjacking Campaign on npm Delivers Persistent Node.js Backdoor
slug: 2026-06-lazarus-npm-brandjacking
description: The Lazarus Group is conducting a brandjacking campaign on npm, using dozens of malicious packages like 'buffer-utilities' to deploy a Node.js backdoor that collects host information, establishes C2 communication, and maintains persistent attacker-controlled code execution, primarily targeting developers.
date: "2026-06-14T09:03:40Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
tags:
  - supply-chain-attack
  - npm
  - brandjacking
  - Lazarus-Group
  - nodejs
  - malware
products:
  - npm package manager
  - Node.js runtime
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://www.sonatype.com/blog/lazarus-groups-latest-brandjacking-campaign-on-npm
iocs:
  - type: domain
    value: www.jsonkeeper.com
ioc_counts:
  domain: 1
rules:
  - title: Detect Node.js Process Connecting to www.jsonkeeper.com
    description: Detects outbound network connections initiated by the Node.js runtime to www.jsonkeeper.com, a domain known to be used by Lazarus Group for payload hosting and C2 in npm brandjacking campaigns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - impact
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect npm install --silent Execution
    description: Detects the execution of 'npm install --silent' which is used by malicious Node.js backdoors to install dependencies for third-stage payloads without generating verbose output.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Creation in .vscode Directory by Node.js
    description: Detects the creation of specific suspicious files (f.js, package.json) within a user's '.vscode' directory, observed in Lazarus Group campaigns for persistence and staging Node.js backdoors. While this rule is configured for Windows, similar patterns apply to Linux/macOS.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.007
      - T1564.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

The Lazarus Group, a state-sponsored threat actor, has launched a sophisticated brandjacking campaign targeting the npm ecosystem, leveraging deceptive package names to abuse developer trust. Active since at least early 2026, this campaign involves dozens of malicious packages, with some seeing up to 500 weekly downloads, designed to appear legitimate or ecosystem-adjacent. These packages, exemplified by "buffer-utilities," go beyond simple typosquatting by employing suffix addition, version mimicry, and embedding legitimate code to evade scrutiny. Upon installation, the packages act as droppers, fetching and executing a multi-stage Node.js backdoor from remote infrastructure like `www.jsonkeeper.com`. This backdoor enables extensive reconnaissance, C2 communication, and the deployment of persistent attacker-controlled code, posing a significant supply chain risk to organizations whose developers use npm.

## Attack Chain

1.  **Initial Access**: A developer installs a malicious npm package (e.g., `buffer-utilities`), mistaking it for a legitimate or related package due to brandjacking techniques like suffix addition, version mimicry, or embedding legitimate code.
2.  **Dropper Execution**: Upon installation or execution, the malicious package's embedded JavaScript code runs, decoding Base64-encoded URLs pointing to external payload servers.
3.  **Payload Fetching**: The malicious code initiates an outbound network connection, typically from a Node.js process, to download additional payloads from command-and-control infrastructure (e.g., `www.jsonkeeper.com`).
4.  **Second-Stage Backdoor Deployment**: The downloaded Node.js backdoor executes, performing host reconnaissance by collecting system information such as hostname, username, operating system, home directory, and active process arguments.
5.  **Command and Control (C2) Communication**: The Node.js backdoor establishes persistent communication with its C2 server to retrieve configuration data and report collected telemetry back to the attackers.
6.  **Persistence & Third-Stage Payload**: Following C2 instructions, the backdoor creates a hidden `.vscode` directory in the user's home folder, downloads further files (including `f.js` and a malicious `package.json`), and executes `npm install --silent` to fetch dependencies before launching `f.js` as a detached background process.
7.  **Ongoing Control & Updates**: The deployed payload includes an update mechanism, allowing it to periodically reconnect to the C2 server, check for newer payload versions, and replace local files, ensuring continuous attacker access and control over the infected system.

## Impact

This campaign represents a critical supply chain threat, particularly for organizations relying on the npm ecosystem for software development. Successful compromise means developers' systems are backdoored, potentially leading to intellectual property theft, credential compromise, further network intrusion, and disruption of development pipelines. The Node.js backdoor functions as a persistent staging framework, allowing the Lazarus Group to deploy additional malicious code and maintain long-term control. While specific victim counts are not disclosed, the wide reach of npm and the reported download numbers (up to 500 weekly for some packages) suggest a broad potential impact across various sectors.

## Recommendation

*   Deploy the Sigma rule "Detect Node.js Process Connecting to `www.jsonkeeper.com`" to your SIEM to identify direct C2 communication.
*   Implement the Sigma rule "Detect `npm install --silent` Execution" to flag automated and potentially malicious package installations.
*   Block network connections to `www.jsonkeeper.com` at the perimeter firewall or DNS resolver, as listed in the IOCs section.
*   Organizations that installed packages associated with Sonatype-2026-003558 (e.g., `buffer-utilities` version `1.0.0`) should remove them and treat affected hosts as potentially compromised.
*   Investigate compromised systems for evidence of second-stage payload execution, hidden `.vscode` directories containing suspicious files like `f.js` or `package.json`, and any unusual process activity.
