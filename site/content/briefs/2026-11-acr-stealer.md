---
brief_id: brief-2026-11-05-acr-stealer
event_id: brief-2026-11-05-acr-stealer
revision: 1
activity_at: "2026-11-05T13:33:56Z"
title: ACR Stealer new payload indicators
slug: 2026-11-acr-stealer
description: New ACR Stealer infostealer payload variants have been identified, warranting immediate investigation across host telemetry.
date: "2026-11-05T13:33:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
references:
  - https://threatfox.abuse.ch/browse/malware/win.acr_stealer/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.acr_stealer
iocs:
  - type: hash_md5
    value: 59a72de45370f1fc1b6bc8d2a78ab538
  - type: hash_sha256
    value: 51691f616ed51be9ef5eb8f52433321491c819a5b641433ce6c9d50168a226b4
ioc_counts:
  hash_md5: 1
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Ingest and block the provided SHA-256 and MD5 hashes on all EDR and AV platforms.
      owner: SOC
      due: 4h
      evidence: New ACR Stealer payload indicators published on ThreatFox
  hunt_leads:
    - lead: Search for recent file creation events matching the provided hashes in EDR telemetry.
      data_needed:
        - EDR file_creation logs
        - File integrity logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: New ACR Stealer payload indicators published on ThreatFox
---

Three new file indicators associated with the ACR Stealer infostealer were reported by ThreatFox on 2026-11-04. The indicators are classified as malicious payloads. No specific delivery mechanisms or exploit vectors were documented in this report.
