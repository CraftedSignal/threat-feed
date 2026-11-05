---
brief_id: brief-2026-11-05-formbook-indicators
event_id: brief-2026-11-05-formbook-indicators
revision: 1
activity_at: "2026-11-05T13:37:28Z"
title: 'Formbook Infostealer: New Payload Indicators'
slug: 2026-11-formbook-indicators
description: ThreatFox identified 21 new samples of the Formbook information stealer, a credential-harvesting malware typically deployed via phishing to capture browser credentials, keystrokes, and clipboard data.
date: "2026-11-05T13:37:28Z"
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
  - infostealer
  - windows
  - phishing
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Formbook is a well-known credential-stealing malware (infostealer) that captures sensitive information such as browser credentials, keystrokes, and clipboard data.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Formbook is a well-known credential-stealing malware (infostealer) that captures sensitive information such as browser credentials, keystrokes, and clipboard data.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.formbook/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook
iocs:
  - type: hash_md5
    value: 2da456cfeaa8e0a6b7af0a88fded3825
  - type: hash_md5
    value: 537b04bfb521dd128d3a6b2580153285
  - type: hash_md5
    value: a6a6b9374b392dd4d8a7d868f35796da
  - type: hash_md5
    value: e9d2c2562a2caf6138dd26da01816bc9
  - type: hash_md5
    value: 12f22fe40d000dd53024311faad8bd1d
  - type: hash_md5
    value: c954acbb7b605ca5904f5a4e5a1ce70f
  - type: hash_md5
    value: f66cba11b7dd462aa7e9759a068d0156
  - type: hash_sha256
    value: d3f328a85e44723ac7816383c7d0daa4aed1a1d120c16c487beb1cd43e91224a
  - type: hash_sha256
    value: 494c9c1ce2d8ac116b3898079469f95061be196fa2e7cce0777bbde5b7ca4aac
  - type: hash_sha256
    value: 3a117682675e884828650c15a83a6c05af1848ae1e3928fcf90fd1c2a7ec68a5
  - type: hash_sha256
    value: 4f03a59c124b154a10126dd253ad037bff96159c0a2827836e8bc0eb04b329de
  - type: hash_sha256
    value: ecbc41f173aaaf4086a92fbbf8d51e006824dc11afffd87fee251b5c73a32025
  - type: hash_sha256
    value: a9894038b6d13c7a1652cff094430c50b1ce80c605497d5df0243eebfcb5ae76
  - type: hash_sha256
    value: eb175a973d117fb34df1c23fa46587c01f68bb014ea192790021be47730661b8
ioc_counts:
  hash_md5: 7
  hash_sha256: 7
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block SHA-256 and MD5 hashes identified in the brief across security stack.
      owner: SOC
      due: 24h
      evidence: Indicators of compromise provided by ThreatFox.
  hunt_leads:
    - lead: Hunt for execution of unknown or unsigned binaries matching the file hashes in the environment.
      technique_id: T1059
      data_needed:
        - EDR FileHash telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: New Formbook payloads reported.
---

On 2026-11-04, ThreatFox reported 21 new samples of the Formbook infostealer. These samples, identified by various hash types, represent active payloads currently circulating. Formbook is a modular information stealer that targets sensitive user data, including credentials stored in web browsers, clipboard contents, and keystrokes.

## Impact

Successful execution of these payloads may lead to the compromise of local user credentials, exfiltration of sensitive session data, and potential lateral movement or secondary malware infections within an environment.

## Recommendation

- Import the provided file hashes (SHA-256 and MD5) into your endpoint detection and response (EDR) or antivirus solutions to block known malicious samples.
- Implement file integrity monitoring and endpoint scanning to identify files matching the observed Formbook hash indicators.
- Review network logs for unusual outbound traffic patterns often associated with Formbook C2 activity, such as persistent connections to unauthorized external domains.
