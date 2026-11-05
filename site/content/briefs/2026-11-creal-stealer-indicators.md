---
brief_id: brief-2026-11-05-creal-stealer-indicators
event_id: brief-2026-11-05-creal-stealer-indicators
revision: 1
activity_at: "2026-11-05T13:33:09Z"
title: 'Creal Stealer: New payload hashes observed'
slug: 2026-11-creal-stealer-indicators
description: ThreatFox identified six new file samples associated with the Creal Stealer malware family on November 4, 2026.
date: "2026-11-05T13:33:09Z"
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
  - https://threatfox.abuse.ch/browse/malware/py.creal_stealer/
iocs:
  - type: hash_md5
    value: 0f1e9ff3fa61acaf74c15bc7178887d6
  - type: hash_sha256
    value: 6fd9ae8104bc4cbd419b5cfbe2a40c4ce63486f8f57585d1071cb3c7d3ddc966
  - type: hash_md5
    value: c927b19e7101727d15b1a28d0c4dc914
  - type: hash_sha256
    value: b99a44bb4bfe7004bdebaec8ecf33a44f3c75650f0f846b90cbefa1199ffe67a
ioc_counts:
  hash_md5: 2
  hash_sha256: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Add identified file hashes to endpoint blocking or alert lists
      owner: SOC
      due: 24h
      evidence: New Creal Stealer indicators provided by ThreatFox
  hunt_leads:
    - lead: Hunt for execution of newly identified file hashes
      data_needed:
        - EDR process creation logs (MD5/SHA256 hashes)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: IOCs provided in the threat report
---

ThreatFox has reported six new indicators of compromise related to the Creal Stealer malware family (py.creal_stealer). These indicators consist of file hashes for payload samples identified on 2026-11-04. No further details regarding the distribution mechanism or post-compromise behavior were provided in this update.

## Recommendation

* Ingest the provided file hashes into your endpoint detection and response (EDR) or file integrity monitoring (FIM) solutions to detect these specific Creal Stealer samples.
* Perform retrospective hunting across historical endpoint logs to identify if any of these identified hashes have been previously executed in the environment.
