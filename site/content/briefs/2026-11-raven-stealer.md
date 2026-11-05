---
brief_id: brief-2026-11-05-raven-stealer
event_id: brief-2026-11-05-raven-stealer
revision: 1
activity_at: "2026-11-05T13:39:32Z"
title: Raven Stealer malware distribution
slug: 2026-11-raven-stealer
description: ThreatFox identified 12 new samples of the Raven Stealer info-stealer targeting Windows environments.
date: "2026-11-05T13:39:32Z"
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
references:
  - https://threatfox.abuse.ch/browse/malware/win.ravenstealer/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.ravenstealer
iocs:
  - type: hash_md5
    value: 0a57fc056b96c08fd3be2f2014b1fa14
  - type: hash_sha256
    value: 768f46d4dc306502ce6b847b1a06509a9301fc44794cc3d70858657278d30ab7
  - type: hash_md5
    value: d365cdc3de06463bc6cf427da426b161
  - type: hash_sha256
    value: fd77ac53f8943ff412fae6815b0335a824e5d671951fe4cb00da84f499f4c372
  - type: hash_md5
    value: e8a94512c9479db23c0e99a1f187662d
  - type: hash_sha256
    value: d2b60bb3b7af913b210a589a5256ea9054c4719e8b626eb2c26626e0a62652f5
  - type: hash_md5
    value: 3bb88057a5cb80e80d7b8394d10fe4e6
  - type: hash_sha256
    value: 08b2c0d4baf3be0329a687354d9257d46d7256c4159c2d826fc507ad0d6abad0
ioc_counts:
  hash_md5: 4
  hash_sha256: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block listed file hashes at the endpoint security layer.
      owner: SOC
      due: 24h
      evidence: New Raven Stealer payload indicators published by ThreatFox.
  hunt_leads:
    - lead: Search for execution of files matching listed hash values.
      technique_id: T1059
      data_needed:
        - Endpoint telemetry (FileCreate, ProcessCreation)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Indicators of compromise provide concrete file hashes for detection.
---

Abuse.ch ThreatFox reported 12 new samples of the Raven Stealer malware on November 4, 2026. These indicators represent newly identified malicious payloads currently associated with the Raven Stealer operation.

## Recommendation
- Block the SHA-256 and MD5 hashes listed in this brief at the enterprise perimeter and endpoint security solutions.
- Implement file integrity monitoring and endpoint detection to identify execution attempts of these hashes.
- Scan historical logs for the presence of these indicators to identify potential prior compromise.
