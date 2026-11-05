---
brief_id: brief-2026-11-05-cloudsyncd-indicators
event_id: brief-2026-11-05-cloudsyncd-indicators
revision: 1
activity_at: "2026-11-05T13:32:39Z"
title: CloudSyncD macOS malware infrastructure
slug: 2026-11-cloudsyncd-indicators
description: The CloudSyncD macOS malware strain is actively utilizing malicious URLs to facilitate botnet command-and-control communications and payload delivery, often masquerading as legitimate jQuery library requests.
date: "2026-11-05T13:32:39Z"
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
  validation_status: Needs environment validation
tags:
  - malware
  - botnet
  - macos
  - command-and-control
references:
  - https://threatfox.abuse.ch/browse/malware/osx.cloudsyncd/
  - https://malpedia.caad.fkie.fraunhofer.de/details/osx.cloudsyncd
iocs:
  - type: url
    value: https://187.77.134.200:8080/index.html/v1/enterprise/administration/assessment/scheduler/combine/jquery-3.3.2.min.js
  - type: url
    value: https://187.124.23.99:8080/index.html/v5/enterprise/infrastructure/decryption/editor/categorize/jquery-3.3.2.min.js
  - type: url
    value: https://dodiihome.com/macos/jquery.js
  - type: url
    value: https://187.124.82.117:8080/index.html/v2.3/enterprise/security/alerting/service/execute/jquery-3.3.2.min.js
  - type: url
    value: https://ecl.zs-catch.com:443/index.html/rc1/enterprise/manufacturing/serialization/parser/query/jquery-3.3.2.min.js
ioc_counts:
  url: 5
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block identified CloudSyncD infrastructure in perimeter security controls.
      owner: SOC
      due: 24h
      evidence: ThreatFox list of active botnet C2 infrastructure.
  enrichment_needed:
    - item: IP/Domain reputation
      owner: CTI
      reason: Determine scope of infrastructure beyond the initial 5 indicators.
      evidence: New infrastructure often appears following indicator publication.
  hunt_leads:
    - lead: Identify outbound connections from macOS assets to non-standard ports (e.g., 8080) hosting URLs containing "jquery" or complex path structures.
      technique_id: T1071.001
      data_needed:
        - Network proxy logs
        - DNS logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Malware masquerading as jQuery requests to C2 URLs.
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering for known malicious indicators.
      owner: IT Operations
      addresses: CloudSyncD C2 traffic
      evidence: Observed malicious infrastructure.
  gaps:
    - Missing host-level telemetry for CloudSyncD persistence or execution on macOS.
---

CloudSyncD (osx.cloudsyncd) is a macOS malware strain identified by ThreatFox as utilizing specific network infrastructure for command-and-control (C2) and payload delivery. Observed traffic often features URL patterns mimicking legitimate jQuery library requests to blend into network traffic. The source confirms the infrastructure is currently active as of November 2026.

## Recommendation

* Block the identified malicious URLs at the corporate proxy and DNS egress points.
* Hunt for outbound HTTPS requests to the identified IPs or domains, particularly those containing long, URI-encoded paths mimicking library file names.
* Leverage the provided URLs to update network perimeter security controls.
