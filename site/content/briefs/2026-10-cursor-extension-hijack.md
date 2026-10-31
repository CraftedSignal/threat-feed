---
brief_id: brief-2026-10-30-cursor-extension-hijack
event_id: brief-2026-10-30-cursor-extension-hijack
revision: 2
activity_at: "2026-10-31T03:18:47Z"
revision_history:
  - revision: 2
    at: "2026-10-31T03:18:47Z"
    checksum: sha256:4e3da345b704838bc24435b337370ca8e122de75bb28430ad343286a87bbc41e
    summary: exploited:true
    changed_fields:
      - claim_state
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
title: Anthropic Claude VS Code extension malicious update distribution
slug: 2026-10-cursor-extension-hijack
description: An unknown actor compromised an official Anthropic distribution channel to push a malicious version of the Claude VS Code extension, enabling persistent SSH backdoors and credential theft on developer workstations.
date: "2026-10-30T22:04:22Z"
lastmod: "2026-10-31T03:17:12Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
  observed_at: "2026-10-31T01:02:57Z"
  confidence: high
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - supply-chain
  - ide
  - trojan
  - persistence
  - exfiltration
  - backdoor
  - credential-theft
  - developer-tools
vendors:
  - Cursor
  - Anthropic
products:
  - Claude Code Extension (v2.1.313)
  - Cursor IDE
  - Claude VS Code Extension (2.1.313)
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    evidence: Anthropic's official Claude Code extension for the Cursor VS Code Marketplace was hijacked and swapped out for a malicious version.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: The malicious extension also attempts to make those connections persistent by registering background processes — for macOS systems, a LaunchAgent; and for Windows, scheduled tasks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053.005
    technique_name: Scheduled Task
    evidence: for Windows, scheduled tasks running with system privileges, plus a fallback Startup script.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    subtechnique_id: T1195.002
    subtechnique_name: Compromise Software Supply Chain
    evidence: It was a supply-chain compromise where the attacker gained access to the official distribution channel.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    subtechnique_id: T1543.001
    subtechnique_name: Launch Agent
    evidence: Attempting to make the reverse SSH tunnel persistent via a LaunchAgent (macOS) or a scheduled task
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: Reporting host details and backdoor status via HTTP POST to /beacon on port 8099.
    confidence_band: high
references:
  - https://www.darkreading.com/cyberattacks-data-breaches/devs-trojanized-claude-code-extension-cursor
  - https://arstechnica.com/security/2026/10/anthropic-vs-code-extension-on-cursor-backdoored-for-nearly-12-hours/
  - https://cursor.com/blog/claude-code-extension-security-notice
  - https://phorion.io/blog/offical-claude-code-vsx-compromise/
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Inventory all developer workstations for Cursor IDE extension installations
      owner: SOC
      due: 24h
      evidence: Source reporting indicates 5,000 users were impacted via extension updates
    - action: Identify all workstations where the Cursor Claude extension was updated on Oct 29, 2026.
      owner: IT Operations
      due: 4h
      evidence: Anyone who installed or updated Anthropic’s VS Code extension from Cursor between 5:27 am ET and 4:35 pm on Thursday should consider themselves affected
    - action: Force credential rotation for any secrets or tokens identified on affected developer machines.
      owner: Development Team
      due: 24h
      evidence: theft of variable names allowed the operator to quickly take inventory of cloud credentials
  hunt_leads:
    - lead: Search for unauthorized modifications to SSH configuration files (~/.ssh/config) on developer endpoints
      technique_id: T1546.001
      data_needed:
        - File integrity monitoring logs
        - Endpoint audit logs for configuration changes
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: It attempts to add an attacker-controlled key to victims' SSH configurations
    - lead: Monitor for newly created scheduled tasks or LaunchAgents related to development tools or unrecognized scripts
      technique_id: T1053.005
      data_needed:
        - Windows Scheduled Task creation logs
        - macOS LaunchAgent/LaunchDaemon directory monitoring
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The malicious extension also attempts to make those connections persistent by registering background processes
    - lead: Identify unauthorized HTTP POST traffic to /beacon on port 8099 from developer endpoints.
      technique_id: T1071.001
      data_needed:
        - Network firewall/proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Reporting host details and backdoor status via HTTP POST to /beacon on port 8099.
    - lead: Identify unexpected LaunchAgent creation or modifications on macOS endpoints.
      technique_id: T1543.001
      data_needed:
        - EDR process creation/file events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attempting to make the reverse SSH tunnel persistent via a LaunchAgent (macOS)
  mitigation_plan:
    - priority: immediate
      action: Upgrade Cursor IDE to the latest version to patch browser-based arbitrary code execution
      owner: IT Operations
      addresses: Cursor browser RCE vulnerability
      evidence: Researchers described an unrelated exploit in Cursor, allowing attackers to deploy arbitrary code to developers' machines via Cursor's built-in browser.
    - priority: immediate
      action: Verify and remove persistence artifacts (LaunchAgents/Scheduled Tasks) on all machines that had extension 2.1.313 installed.
      owner: IT Operations
      addresses: Persistence mechanisms
      evidence: The new version published by Anthropic doesn’t clear the infection if your device was compromised
updates:
  - at: "2026-10-30T22:04:38Z"
    level: L1
    summary: added coverage for Claude VS Code Extension (2.1.313)
    sources:
      - ars-security
    source_urls:
      - https://arstechnica.com/security/2026/10/anthropic-vs-code-extension-on-cursor-backdoored-for-nearly-12-hours/
  - at: "2026-10-31T03:17:12Z"
    level: L3
    summary: exploited:true
    sources:
      - microsoft-threat-intel
    source_urls:
      - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
---

Between approximately 05:27 and 16:35 ET on October 29, 2026, a malicious version (2.1.313) of the Anthropic Claude VS Code extension was distributed via the official Cursor marketplace. The compromise was a supply-chain attack resulting from unauthorized access to Anthropic's distribution account. The malicious extension executed host reconnaissance, attempted to establish persistent SSH access, and exfiltrated environment variables and configuration files. Anthropic has since released version 2.1.314, though this update does not remove persistence mechanisms installed by the malicious 2.1.313 version.

## Attack Chain

1. Unauthorized access to the Anthropic official account on the Cursor extension marketplace.
2. Publication of malicious extension version 2.1.313, superseding the legitimate 2.1.312 version.
3. Automatic distribution to developer workstations configured for auto-updates.
4. Execution of reconnaissance commands to collect host/user data and environment variable inventory.
5. Attempted modification of SSH configurations (`authorized_keys`) and initialization of a reverse SSH tunnel.
6. Persistence established via platform-specific mechanisms (LaunchAgents on macOS; scheduled tasks on Windows).
7. Exfiltration of configuration and credential data via HTTP POST beacons on port 8099.

## Impact

Up to 5,000 developers' workstations were potentially exposed. Confirmed impact includes local host information gathering, potential theft of cloud credentials and API tokens stored in environment variables, and unauthorized persistence via SSH and system-level scheduled tasks.

## Recommendation

1. Audit all developer workstations for the presence of the malicious extension version 2.1.313.
2. If version 2.1.313 was present, perform a full forensic sweep; updating to version 2.1.314 does not remediate established persistence.
3. Rotate all API keys, cloud credentials, and SSH keys present on affected developer machines.
4. Check for unauthorized entries in `~/.ssh/authorized_keys` (Linux/macOS) or Windows-equivalent SSH configurations.
5. Inspect system-level persistence mechanisms, specifically checking for newly created LaunchAgents on macOS or suspicious scheduled tasks running as SYSTEM on Windows.
6. Monitor network egress for HTTP POST traffic on port 8099.
