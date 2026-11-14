---
brief_id: brief-2026-11-12-screenconnect-attacks
event_id: brief-2026-11-12-screenconnect-attacks
revision: 4
activity_at: "2026-11-14T02:10:03Z"
revision_history:
  - revision: 2
    at: "2026-11-12T09:06:49Z"
    checksum: sha256:b71d00f5ec7ae8dc03cc1b4c07c9b77b55220858777962ef2b42b555a7179dd6
    summary: new IOCs
    changed_fields:
      - claim_state
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.sophos.com/en-us/blog/malicious-screenconnect-deployments-observed
  - revision: 3
    at: "2026-11-12T16:48:01Z"
    checksum: sha256:de3f9a9d893c3076f301842d0938694d5e146545c448891aa930a738ae2bcc50
    summary: added CVE-2026-84869
    changed_fields:
      - cpes
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://therecord.media/connectwise-screenconnect-breaches-third-party-tool
  - revision: 4
    at: "2026-11-14T02:10:03Z"
    checksum: sha256:58b73fcc1309eb57fd045ccdf43aa16e51edf0592c81264036d67abdf09a2f7e
    summary: new IOCs
    changed_fields:
      - cves
      - exploitation_evidence
      - iocs
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.huntress.com/blog/fake-crypto-exchange-sessions-screenconnect
title: Unauthorized Access and Rogue Client Deployment in ScreenConnect Environments
slug: 2026-11-screenconnect-attacks
description: Threat actors are leveraging compromised credentials or hijacked operator sessions to gain access to ScreenConnect panels, where they deploy rogue clients and malicious toolkits for persistent access.
date: "2026-11-12T06:12:36Z"
lastmod: "2026-11-14T02:09:29Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-11-12T06:12:36Z"
  confidence: high
source_assessment:
  reliability: D
  credibility: "2"
  rating: D2
  likelihood: likely
cpes:
  - cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*
tags:
  - screenconnect
  - malware
  - persistence
  - lateral-movement
vendors:
  - ConnectWise
products:
  - ScreenConnect
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Current telemetry points to compromised credentials or hijacked operator sessions to gain initial access.
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: ScreenConnect scripts staging batch files and using PowerShell with execution-policy bypass to retrieve a second-stage script.
cves:
  - id: CVE-2026-84869
    cvss: 9.9
    epss: 0.00924
    kev: true
    kev_status: "true"
references:
  - https://thehackernews.com/2026/11/screenconnect-attacks-target-at-least.html
  - https://www.sophos.com/en-us/blog/malicious-screenconnect-deployments-observed
  - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
  - https://www.securityweek.com/hackers-deploy-malware-in-fresh-screenconnect-campaign/
  - https://therecord.media/connectwise-screenconnect-breaches-third-party-tool
  - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
  - https://www.huntress.com/blog/fake-crypto-exchange-sessions-screenconnect
iocs:
  - type: ip
    value: 185.99.255.28
  - type: url
    value: http://ns.mo7sen.dev/EadF.php?p=4
  - type: ip
    value: 74.208.158.106
ioc_counts:
  ip: 2
  url: 1
rules:
  - title: Suspicious ScreenConnect Run Command Activity
    description: Detects the use of Run Command to deploy suspected malicious scripts associated with the SCKit toolkit.
    platform: sigma
    severity: critical
    data_sources:
      - process_creation
      - windows
rules_count: 1
updates:
  - at: "2026-11-12T09:06:03Z"
    level: L1
    summary: new IOCs
    sources:
      - sophos-xops
    source_urls:
      - https://www.sophos.com/en-us/blog/malicious-screenconnect-deployments-observed
  - at: "2026-11-12T16:44:06Z"
    level: L2
    summary: added CVE-2026-84869
    sources:
      - therecord
    source_urls:
      - https://therecord.media/connectwise-screenconnect-breaches-third-party-tool
  - at: "2026-11-14T02:09:24Z"
    level: L3
    summary: KEV CVE-2026-84869
    sources:
      - microsoft-threat-intel
    source_urls:
      - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
  - at: "2026-11-14T02:09:29Z"
    level: L1
    summary: new IOCs
    sources:
      - huntress
    source_urls:
      - https://www.huntress.com/blog/fake-crypto-exchange-sessions-screenconnect
---

ConnectWise is investigating reports of unauthorized access to ScreenConnect environments, affecting at least 288 endpoints across 48 organizations. The activity involves the use of the 'Run Command' feature to deploy rogue ScreenConnect clients. ConnectWise has urged partners to disable five third-party extensions as a precautionary measure while investigations continue.

## Attack Chain
1. Initial Access: Attackers gain access to cloud-hosted ScreenConnect panels, likely via compromised credentials or hijacked operator sessions.
2. Payload Delivery: Attackers utilize the 'Run Command' feature to deploy rogue ScreenConnect clients and an encrypted malicious toolkit (SCKit).
3. Persistence and Lateral Movement: The toolkit creates a persistent backdoor, adds Microsoft Defender exclusions, and attempts to steal browser sessions and authentication tokens from connected technician workstations to pivot to other managed panels.

## Recommendation
- Disable the identified third-party extensions: Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, and RMM+ Password Link.
- Review ScreenConnect Run Command history for unauthorized activity.
- Monitor for suspicious sign-ins, unexpected MFA prompts, and new administrator accounts.
- Inspect managed endpoints for the presence of unauthorized ScreenConnect clients or unexpected tools such as 'TrapWatch'.
