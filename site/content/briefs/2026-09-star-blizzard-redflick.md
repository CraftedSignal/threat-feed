---
title: Star Blizzard Evolution and RedFlick Malware Delivery Technique
slug: 2026-09-star-blizzard-redflick
description: Russian state actor Star Blizzard has shifted to large-scale phishing campaigns and adopted the RedFlick delivery technique to deploy the CosmicPulse backdoor via scheduled tasks with minimal user interaction.
date: "2026-09-29T19:17:03Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Star Blizzard
tags:
  - phishing
  - espionage
  - redflick
  - cosmicpulse
  - star-blizzard
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Respondents received a RedFlick lure attachment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: RedFlick, a malware delivery technique that helps evade detection by initiating a set of scheduled tasks to deploy the actor’s custom backdoor.
    confidence_band: high
rules:
  - title: Detect Suspicious Scheduled Task Creation
    description: Detects the creation of scheduled tasks that execute commands, commonly associated with backdoor deployment stages like RedFlick.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
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
    - action: Review scheduled task logs for signs of unauthorized persistence patterns described in the RedFlick technique.
      owner: SOC
      due: 24h
      evidence: Source describes initiation of scheduled tasks as part of the infection flow.
  hunt_leads:
    - lead: Mass-mailing anomalies in mail gateway logs matching the listed phishing subject themes.
      technique_id: T1566
      data_needed:
        - Mail gateway logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Microsoft observed this actor shift to large-scale phishing campaigns.
  mitigation_plan:
    - priority: short_term
      action: Enable robust email authentication (SPF, DKIM, DMARC) and implement sender identity validation to disrupt impersonation attempts.
      owner: IT Operations
      addresses: Phishing delivery
      evidence: Attacker shifts to large-scale phishing to reach more targets.
---

Since January 2026, the Russian state-sponsored threat actor Star Blizzard (subordinate to FSB Centre 18) has evolved its operational tradecraft to include large-scale phishing campaigns and a novel malware delivery mechanism dubbed "RedFlick." This pivot represents a significant departure from previous, more targeted spear-phishing operations, allowing the actor to scale operations significantly by utilizing automated mass-mailing platforms. The RedFlick technique streamlines the infection chain, requiring only a single user interaction to initiate the deployment of the custom CosmicPulse backdoor. These operations target individuals and institutions supporting Ukraine, including government officials, NGOs, think tanks, and international financial organizations, particularly within the United States and the United Kingdom. With over 100 organizations affected, this evolution indicates a persistent and adaptive threat capable of rapid TTP iteration in response to public disclosure and defensive hardening.

## Attack Chain

1. The actor conducts reconnaissance to identify targets associated with Ukraine, financial policy, or international relations.
2. Mass-phishing emails are distributed using accounts on compromised websites to bypass reputation filters, impersonating legitimate organizations or events (e.g., roundtable discussions).
3. The victim receives an email containing an attachment which, when opened, initiates the RedFlick infection flow.
4. RedFlick executes locally, reducing user friction by requiring only a single interaction compared to legacy ClickFix-based chains.
5. The infection process configures a scheduled task on the target system to achieve persistence.
6. The scheduled task executes a command to download and install the CosmicPulse backdoor from actor-controlled infrastructure.
7. The CosmicPulse backdoor enables remote access, providing the threat actor with persistent entry for cyberespionage objectives.

## Impact

The evolution to RedFlick and large-scale phishing has enabled Star Blizzard to successfully compromise over 100 organizations across the United States and the United Kingdom. Victims include government officials, think tanks, NGOs, and financial institutions involved in international policy and support for Ukraine. Successful compromise allows the actor to perform persistent cyberespionage, potentially resulting in the exfiltration of sensitive diplomatic, strategic, and financial intelligence.

## Recommendation

Prioritize hardening against phishing and malicious task creation by implementing the following:
- Deploy endpoint detection rules to monitor for suspicious scheduled task creation and execution chains.
- Implement email filtering controls that block messages originating from known compromised infrastructure and investigate mass-mail patterns.
- Audit scheduled tasks periodically for unauthorized or unusual commands, specifically looking for tasks spawned from common user document folders.
- Review network egress logs for connections to unknown domains following the execution of suspicious user-space processes.
