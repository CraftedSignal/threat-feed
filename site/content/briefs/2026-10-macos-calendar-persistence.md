---
title: Suspicious macOS Calendar File Modification for Persistence
slug: 2026-10-macos-calendar-persistence
description: Adversaries may achieve persistence on macOS by modifying calendar (.ics) files to trigger the execution of malicious programs at recurring intervals.
date: "2026-10-07T16:40:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - macos
  - endpoint
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Adversaries may create a custom calendar notification procedure to execute a malicious program at a recurring interval to establish persistence.
    confidence_band: high
references:
  - https://labs.reversec.com/posts/2020/10/operationalising-calendar-alerts-persistence-on-macos
  - https://github.com/FSecureLABS/CalendarPersist
  - https://github.com/D00MFist/PersistentJXA/blob/master/CalendarPersist.js
rules:
  - title: Detect Suspicious Calendar File Modification
    description: Detects unauthorized processes modifying .ics calendar files, a technique used to establish persistence via event-triggered execution.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546
    data_sources:
      - file_event
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect unauthorized .ics file modifications.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rule requirement.
  hunt_leads:
    - lead: Search for non-system binaries modifying files under ~/Library/Calendars/.
      technique_id: T1546
      data_needed:
        - File integrity logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Technique relies on modification of files in this specific directory.
  mitigation_plan:
    - priority: medium
      action: Identify and whitelist legitimate third-party calendar software.
      owner: IT Operations
      addresses: False positive management
      evidence: Rule documentation notes on false positives.
---

Adversaries targeting macOS systems may leverage the Calendar application to establish persistence. By programmatically modifying .ics calendar files stored within the ~/Library/Calendars/ directory, attackers can configure malicious event triggers that execute unauthorized code or scripts at recurring intervals. This technique exploits the legitimate functionality of macOS to notify users of calendar events, repurposing it as a mechanism for repeated, stealthy execution of malicious payloads. Defenders should monitor for unexpected processes interacting with the Calendar directory, as legitimate calendar management is typically confined to a specific set of system binaries and trusted applications. This threat is particularly relevant for environments where users rely heavily on calendar-based workflows, as the persistence mechanism is difficult to detect through standard user-level inspection of the Calendar interface.

## Impact

Successful exploitation allows for long-term persistence on macOS endpoints, enabling the recurring execution of malware, staging of further tools, or beaconing to command-and-control infrastructure. Because the execution is tied to the Calendar database, it can survive reboots and may bypass simple process-based monitoring if the attacker utilizes native or trusted signing identities to modify the files.

## Recommendation

Prioritize the deployment of behavioral monitoring for file modifications within the User Library directory.

* Deploy the provided Sigma rule to detect unauthorized process interactions with .ics files in the calendar directory.
* Audit administrative access to the ~/Library/Calendars/ folder to ensure only expected processes perform modifications.
* Investigate alerts by correlating the process path with known baseline activity for the affected endpoint.
* Exclude legitimate third-party calendar sync tools from the detection logic to reduce noise once those binaries are validated.
