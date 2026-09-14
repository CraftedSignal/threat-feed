---
title: Detection of Newly Observed Legitimate Network Scanning Tools
slug: 2026-09-newly-seen-network-scanners
description: Adversaries frequently utilize legitimate network scanning utilities like SoftPerfect Network Scanner and Advanced IP Scanner for reconnaissance following initial compromise to map internal network topology and identify lateral movement targets.
date: "2026-09-14T18:54:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - reconnaissance
  - windows
  - endpoint-detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: Adversaries commonly use these legitimate scanners during post-compromise discovery to map live hosts, open ports, and reachable systems.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Adversaries commonly use these legitimate scanners during post-compromise discovery to map live hosts, open ports, and reachable systems.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a
  - https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/
  - https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/
rules:
  - title: Newly Seen Commonly Abused Network Scanner Execution
    description: Detects the first-time execution of SoftPerfect Network Scanner or Advanced IP/Port Scanner on a Windows host, a common technique for post-compromise network discovery.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
      - T1046
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect and alert on the presence of these scanning binaries.
      owner: Detection Engineering
      due: 48h
      evidence: This rule identifies unauthorized post-compromise reconnaissance activity.
  hunt_leads:
    - lead: Search historical logs for evidence of these specific process names to identify past unauthorized reconnaissance.
      technique_id: T1046
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Historical execution history can reveal undetected, previous compromises.
---

Post-compromise reconnaissance relies heavily on tools that can quickly enumerate network assets, open ports, and reachable services. Threat actors consistently abuse legitimate, dual-use administrative utilities, specifically SoftPerfect Network Scanner and Advanced IP/Port Scanner, to gain situational awareness within a victim network. These tools are lightweight, portable, and often overlooked by security controls because they are signed, legitimate software.

The use of these tools is a well-documented precursor to lateral movement and ransomware deployment, as seen in various intrusion case studies, including those associated with the RansomHub and BlackByte operations. Defenders should focus on baseline monitoring to identify these binaries when they are introduced into an environment for the first time or executed from non-standard locations, as this behavioral shift often indicates an adversary attempting to map the environment after gaining initial access.

## Impact

Successful reconnaissance with these tools enables attackers to identify critical infrastructure, domain controllers, and high-value servers. If left undetected, this mapping activity facilitates efficient lateral movement, privilege escalation, and data exfiltration, ultimately increasing the likelihood of widespread ransomware deployment or persistent data theft within the targeted organization.

## Recommendation

Prioritize the identification of "newly seen" processes within your environment to catch baseline deviations. 

- Enable process creation logging via Sysmon (Event ID 1) or Windows Security Event Logs to capture the execution of scanning binaries mentioned in the Sigma rules below.
- Deploy detection logic to flag the first-time execution of identified scanners on any host within the infrastructure.
- Establish a process for analysts to investigate alerts triggered by these scanners to differentiate between authorized IT administrative tasks and unauthorized adversary activity.
