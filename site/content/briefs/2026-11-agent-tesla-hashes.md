---
brief_id: brief-2026-11-05-agent-tesla-hashes
event_id: brief-2026-11-05-agent-tesla-hashes
revision: 1
activity_at: "2026-11-05T13:34:09Z"
title: 'Agent Tesla: New indicators of compromise identified'
slug: 2026-11-agent-tesla-hashes
description: Twelve new Agent Tesla information stealer samples have been identified, requiring endpoint hash scanning and retrospective threat hunting across Windows environments.
date: "2026-11-05T13:34:09Z"
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
  - information-stealer
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Agent Tesla is a .NET-based information stealer capable of capturing credentials, keystrokes, and clipboard data.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.agent_tesla/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla
iocs:
  - type: hash_md5
    value: 9e1eccf2d525a5f1a36eff822229607e
  - type: hash_sha256
    value: 5df8d19faea9fab8141875fe86f844291cace363fec5c764e8b5cc11da141b32
  - type: hash_md5
    value: 9ec8a802fe2a11b72b83fa027fb651ed
  - type: hash_sha256
    value: ed0f1d1b4673e50dfda972458c7a37b3291086e4f3d72a4464ac92b16b524cf3
  - type: hash_md5
    value: 5c8f88f2c20f31ee0c07917580b694c8
  - type: hash_sha256
    value: adfe94a99972c39c3e53cfaa9b92546b9ff5be4e75b20bc4a0c615a88aac74eb
  - type: hash_md5
    value: 57519761cd285b232694e5afc4e3c8bf
  - type: hash_sha256
    value: 071e3e45090fd134fad750dff5cfbf2c873ed5c3d1c6826d61bb5ab0bbab1de3
ioc_counts:
  hash_md5: 4
  hash_sha256: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Update blocklists with provided file hashes.
      owner: SOC
      due: 24h
      evidence: New Agent Tesla payloads identified on 2026-11-04.
  hunt_leads:
    - lead: Retrospective search for known Agent Tesla malicious hashes across endpoint logs.
      technique_id: T1059
      data_needed:
        - Endpoint file creation or process execution logs containing hash values.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Twelve new Agent Tesla payloads reported on 2026-11-04.
---

Twelve new Agent Tesla information stealer payloads were identified on 2026-11-04. Agent Tesla is a .NET-based malware family known for credential harvesting, keystroke logging, and clipboard exfiltration. These indicators are reported by the ThreatFox community and provide high-confidence artifacts for identifying recent infections.

## Impact
Confirmed impact includes the presence of unauthorized information stealer binaries on Windows systems. Possible impact includes credential theft, unauthorized access to sensitive accounts, and exfiltration of system data.

## Recommendation
- Implement file integrity monitoring or endpoint protection scans using the provided SHA-256 and MD5 hashes.
- Perform retrospective hunts in endpoint telemetry for the execution of files matching the reported hashes.
- Review network egress logs for connections to unauthorized C2 infrastructure often associated with Agent Tesla patterns.
