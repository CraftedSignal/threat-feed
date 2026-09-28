---
title: TerminalFix Social Engineering Campaign Using Cloudflare Lures
slug: 2026-09-terminalfix
description: The TerminalFix campaign uses social engineering to trick users into pasting malicious PowerShell commands under the guise of a Cloudflare verification process, leading to secondary payload execution.
date: "2026-09-28T16:10:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - powershell
  - execution
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The TerminalFix campaign uses malicious PowerShell commands executed via user copy-paste.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Users are targeted via browser-based lures designed to facilitate initial execution.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
rules:
  - title: Potential TerminalFix Cloudflare Lure in PowerShell
    description: Detects PowerShell script blocks containing common Cloudflare lure text used in the TerminalFix campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
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
    - action: Deploy PowerShell Script Block Logging across the domain.
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Search 4104 logs for common Cloudflare-related lure strings.
      technique_id: T1204.004
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Configure GPO to enable PowerShell Script Block Logging.
      owner: IT Operations
---

The TerminalFix campaign is a sophisticated social engineering attack observed as of August 2026. Attackers leverage browser-based overlays that present fake Cloudflare verification prompts to users. These prompts instruct the victim to copy a snippet of text and paste it into Windows Terminal or PowerShell to complete a supposed security check. When executed, the PowerShell script block performs malicious actions, including downloading secondary payloads, extracting archives, and launching follow-on scripts or executables. This campaign demonstrates a reliance on user-assisted execution of malicious commands, bypassing initial browser-based defenses. Defenders must focus on visibility into PowerShell script block execution to detect the specific language patterns associated with these lures.

## Attack Chain

1. User encounters a malicious website posing as a security-gated portal, triggering a fake Cloudflare verification prompt.
2. The website instructs the user to open Windows Terminal or PowerShell and paste a provided command snippet.
3. The victim executes the PowerShell script, which is recorded via PowerShell Script Block Logging (Event ID 4104).
4. The script outputs deceptive text to the console, such as "Cloudflare ID:" or "I am not a robot," to maintain the illusion of a legitimate security process.
5. The PowerShell script initiates background tasks to retrieve remote payloads, typically involving download or web-request commands.
6. The script extracts downloaded archives to a user-writable or temporary system directory.
7. The script executes secondary malicious payloads, such as batch files, VBScripts, or unsigned executables, to establish persistence or facilitate further intrusion.

## Impact

Successful exploitation leads to unauthorized code execution on the target host. This allows for the deployment of reverse tunnels, persistent backdoors, or additional malware stages, potentially compromising credentials and sensitive information on the affected Windows endpoints.

## Recommendation

1. Enable and collect PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture the full context of executed scripts.
2. Deploy the provided Sigma rule to monitor for specific lure-related strings in PowerShell execution telemetry.
3. Proactively hunt for instances where PowerShell processes originate from user-interactive activities following browser navigation events.
4. Educate users that legitimate Cloudflare or security verification processes never require the manual execution of commands in a terminal.
5. Implement strict controls on command-line execution and use EDR/EPP solutions to alert on the launch of unexpected executables or scripts in temporary directory paths.
