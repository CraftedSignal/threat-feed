---
title: Persistence via macOS Shell Profile Curl Execution
slug: 2026-10-macos-shell-profile-persistence
description: Threat actors achieve persistence on macOS by injecting curl commands into shell profile scripts to execute malicious payloads automatically upon user login or terminal initialization.
date: "2026-10-05T12:01:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - c2
  - macos
  - shell
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Threat actors inject curl commands into these profiles to download and execute additional payloads each time the user opens a terminal.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Threat actors inject curl commands into these profiles to download and execute additional payloads.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Shell profile scripts (.zshrc, .bashrc, .bash_profile, .zprofile) execute automatically when users open new terminal sessions.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_curl_execution_via_shell_profile.toml
  - https://attack.mitre.org/techniques/T1546/004/
rules:
  - title: Detect Curl Execution via Shell Profile
    description: Detects when curl is executed via a shell profile upon login, indicating potential persistence or malicious payload delivery.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1105
      - T1546.004
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search shell configuration files for curl or wget commands
      technique_id: T1546.004
      data_needed:
        - File integrity monitoring or host-based file search
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source states review shell profile files to identify injected curl command
  mitigation_plan:
    - priority: short_term
      action: Remove unauthorized curl entries from shell profile scripts
      owner: IT Operations
      addresses: T1546.004
      evidence: Remove the malicious curl command from the affected shell profile file immediately.
  gaps:
    - Lack of historical data on existing persistent configuration entries
---

Threat actors utilize macOS shell configuration files, including .zshrc, .bashrc, .bash_profile, and .zprofile, as a persistence mechanism to maintain access and facilitate secondary payload delivery. By injecting commands into these scripts, attackers ensure that malicious logic is executed every time a user initiates a shell session or logs into the system. This method is particularly effective for beaconing and downloading follow-on stages of an attack. Defenders should monitor for unexpected curl activity originating from child processes of shells that were invoked by login processes. This activity creates a reliable mechanism that persists across system reboots and provides attackers with a consistent execution window.

## Attack Chain

1. Attacker gains initial access to the target macOS system.
2. Attacker identifies a user shell profile script, such as ~/.zshrc or ~/.bash_profile, to modify.
3. Attacker injects a malicious curl command with download flags (e.g., -o, -F) into the selected shell profile file.
4. The user logs into the system or opens a new terminal window.
5. The login process spawns a shell (bash, zsh, or sh).
6. The shell parses the modified configuration file and executes the injected curl command.
7. The curl command reaches out to the attacker's C2 server to download secondary payloads or beacons.
8. The downloaded payload executes on the endpoint, completing the persistence or command-and-control cycle.

## Impact

Successful exploitation allows for long-term persistence on macOS endpoints, enabling attackers to maintain command-and-control access, exfiltrate data, or deploy secondary malware. Because these scripts run with the privileges of the user, attackers can access sensitive environment variables, tokens, and files accessible to the user, potentially escalating their impact within the organization.

## Recommendation

1. Deploy the provided Sigma rule to detect suspicious curl execution following a login-initiated shell event.
2. Perform periodic audits of user shell profiles (.zshrc, .bashrc, .bash_profile) to identify unauthorized modifications.
3. Review file modification timestamps on critical configuration files to detect the timing of potential persistence establishment.
4. Block known malicious domains at the network perimeter if identified through endpoint analysis of downloaded artifacts.
5. Reset compromised user shell profiles from known-good backups or standard organizational templates.
