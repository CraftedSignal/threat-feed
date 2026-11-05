---
brief_id: brief-2026-11-05-meterpreter-indicators
event_id: brief-2026-11-05-meterpreter-indicators
revision: 1
activity_at: "2026-11-05T13:38:34Z"
title: 'Meterpreter: New indicators of compromise'
slug: 2026-11-meterpreter-indicators
description: ThreatFox documented three new file hashes associated with the Meterpreter post-exploitation framework on November 4, 2026.
date: "2026-11-05T13:38:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Data extracted directly from verified ThreatFox records.
tags:
  - meterpreter
  - c2
  - malware
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: These payloads are primarily used for command and control and remote administrative capabilities on Windows systems.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.meterpreter/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter
iocs:
  - type: hash_md5
    value: 5195f92e00684f661c61b4c3dd134f98
  - type: hash_sha256
    value: d4a8ce2863d7717a1e5787c8b094098ec4e92e2379d26089bee2e235948a4446
ioc_counts:
  hash_md5: 1
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block the provided MD5 and SHA-256 hashes on all endpoint protection platforms
      owner: SOC
      due: 24h
      evidence: Indicators are associated with Meterpreter payloads reported by ThreatFox
  hunt_leads:
    - lead: Search endpoint logs for the presence of the provided file hashes
      technique_id: T1059.003
      data_needed:
        - EDR FileCreate, FileExecute, or ProcessCreation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: IOCs provided by ThreatFox for active win.meterpreter payloads
---

ThreatFox has published new indicators of compromise (IOCs) related to the Meterpreter post-exploitation framework, specifically categorized as Windows payloads. These indicators were observed between 04:56 and 14:34 UTC on November 4, 2026, and were reported by the community contributors Grim and Tuxxin. Meterpreter is commonly utilized by threat actors for post-exploitation activities, including command-and-control, privilege escalation, and lateral movement.

## Impact

Successful deployment of Meterpreter on an endpoint allows an attacker to maintain persistent, interactive access to the affected system, enabling file system navigation, process manipulation, and the exfiltration of sensitive data.

## Recommendation

- Implement file integrity monitoring and scan endpoints for the provided hashes.
- Configure SIEM or EDR solutions to trigger alerts on the execution of files matching the provided SHA-256 or MD5 hashes.
- Review historical endpoint telemetry for any execution activity associated with these specific file identifiers.
