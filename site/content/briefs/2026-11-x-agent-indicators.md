---
brief_id: brief-2026-11-05-x-agent-indicators
event_id: brief-2026-11-05-x-agent-indicators
revision: 1
activity_at: "2026-11-05T13:32:50Z"
title: X-Agent modular backdoor file indicators
slug: 2026-11-x-agent-indicators
description: Three new file hashes associated with the X-Agent macOS backdoor were identified and added to ThreatFox on November 4, 2026.
date: "2026-11-05T13:32:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - malware
  - backdoor
  - macos
  - x-agent
references:
  - https://threatfox.abuse.ch/browse/malware/osx.xagent/
  - https://malpedia.caad.fkie.fraunhofer.de/details/osx.xagent
iocs:
  - type: hash_md5
    value: 7ededc7f1886835c56a058f3587dc966
  - type: hash_sha256
    value: 30a43e3a64b90e8853daaa61ca5c2a0e6b5f3e7126e47b3ab6d826243e9ca14b
ioc_counts:
  hash_md5: 1
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Block the listed file hashes on all macOS endpoints
      owner: SOC
      due: 24h
      evidence: Indicators identified as active X-Agent payloads
  hunt_leads:
    - lead: Search for recent file creations or executions matching the identified hash values
      data_needed:
        - EDR telemetry (file_creation, process_start)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: New X-Agent indicators published on 2026-11-04
---

ThreatFox has reported three new file indicators associated with the X-Agent (OSX) malware family. X-Agent is a modular backdoor historically utilized in espionage campaigns. These indicators are identified as payloads and were first observed on November 4, 2026.

## Recommendation

* Ingest the provided SHA-256 and MD5 file hashes into endpoint detection and response (EDR) blocklists.
* Perform retrospective hunting across all managed macOS endpoints for the presence of these file hashes.
* Ensure file integrity monitoring (FIM) is active on critical system paths to detect unauthorized executable deployment.
