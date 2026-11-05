---
brief_id: brief-2026-11-05-smartapesg-indicators
event_id: brief-2026-11-05-smartapesg-indicators
revision: 1
activity_at: "2026-11-05T13:32:17Z"
title: 'SmartApeSG malware: New payload delivery infrastructure'
slug: 2026-11-smartapesg-indicators
description: ThreatFox identified three new indicators of compromise, including a domain and two URLs, utilized by the SmartApeSG malware family for payload delivery.
date: "2026-11-05T13:32:17Z"
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
  - https://threatfox.abuse.ch/browse/malware/js.smartapesg/
  - https://malpedia.caad.fkie.fraunhofer.de/details/js.smartapesg
iocs:
  - type: domain
    value: medlarportcullis.org
  - type: url
    value: https://medlarportcullis.org/proxy/beta-schema
  - type: url
    value: https://medlarportcullis.org/proxy/token-response.js
ioc_counts:
  domain: 1
  url: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block the domain medlarportcullis.org at the enterprise DNS resolver.
      owner: SOC
      due: 24h
      evidence: Source identifies domain as SmartApeSG infrastructure.
    - action: Block access to the URLs on medlarportcullis.org via proxy or EDR web filtering.
      owner: SOC
      due: 24h
      evidence: Source identifies URLs as SmartApeSG payload delivery endpoints.
  hunt_leads:
    - lead: Search for recent outbound HTTP/HTTPS requests to the identified domain and URLs.
      data_needed:
        - Proxy logs
        - DNS logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Infrastructure is associated with active payload delivery.
---

ThreatFox has reported three new indicators of compromise (IOCs) associated with the SmartApeSG malware family. These indicators were first observed on November 4, 2026, and are classified under the payload delivery category. The infrastructure consists of one domain and two specific file paths used for delivery.
