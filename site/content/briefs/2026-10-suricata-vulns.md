---
brief_id: brief-2026-10-30-suricata-vulns
event_id: brief-2026-10-30-suricata-vulns
revision: 1
activity_at: "2026-10-30T03:15:06Z"
title: 'Suricata: Multiple denial-of-service vulnerabilities'
slug: 2026-10-suricata-vulns
description: Suricata versions prior to 8.0.8 contain multiple high-severity vulnerabilities in protocol processing that can lead to memory exhaustion, CPU exhaustion, or service crashes.
date: "2026-10-30T03:15:06Z"
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
  validation_status: All claims derived directly from the provided oss-security advisory.
tags:
  - denial-of-service
  - network-security
  - patch-management
vendors:
  - Suricata
products:
  - Suricata (< 8.0.8)
references:
  - https://seclists.org/oss-sec/2026/q4/438
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Suricata to version 8.0.8 or later
      owner: IT Operations
      due: 48h
      evidence: Suricata 8.0.8 was released addressing a number of vulnerabilities.
  hunt_leads:
    - lead: Monitor for Suricata service instability or crashes
      technique_id: T1499
      data_needed:
        - Systemd/syslog service status logs
        - Suricata application logs (stats.log)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerabilities involve unbounded transaction retention, quadratic complexity, and memory exhaustion that can crash Suricata.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Suricata to version 8.0.8 or later
      owner: IT Operations
      addresses: 'Issues #9085, #9101, #9104, #9133'
      evidence: Suricata 8.0.8 was released addressing a number of vulnerabilities.
---

Suricata version 8.0.8 addresses several high-severity vulnerabilities affecting protocol inspection. These flaws, identified in internal issues #9085, #9101, #9104, and #9133, allow for denial-of-service conditions through resource exhaustion or application crashes.

## Impact
The identified vulnerabilities can cause Suricata to cease inspection or crash when processing specifically crafted network traffic, potentially creating a blind spot in network monitoring. Observed impacts include CPU exhaustion, memory exhaustion, and service termination.

## Recommendation
- Upgrade all Suricata deployments to version 8.0.8 or later immediately.
- Review network infrastructure logs for evidence of anomalous spikes in resource usage on Suricata sensors corresponding to the protocol parsing activities (TFTP, SIP, HTTP/2, DoH/2).
