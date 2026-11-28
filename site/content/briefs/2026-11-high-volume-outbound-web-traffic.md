---
brief_id: brief-2026-11-28-high-volume-outbound-web-traffic
event_id: brief-2026-11-28-high-volume-outbound-web-traffic
revision: 1
activity_at: "2026-11-28T20:45:41Z"
title: High volume outbound web traffic detection
slug: 2026-11-high-volume-outbound-web-traffic
description: A detection analytic identifies potential data exfiltration by monitoring for outbound web traffic exceeding 1GB within a 2-minute window.
date: "2026-11-28T20:45:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic sourced from official Splunk ESCU repository.
tags:
  - data-exfiltration
  - network-anomaly
  - hellcat-ransomware
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: The following analytic detects a high volume of outbound web traffic... This activity is significant as it may indicate potential data exfiltration by malware or malicious insiders.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/web/high_volume_of_bytes_out_to_url.yml
  - https://attack.mitre.org/techniques/T1567/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the high volume outbound traffic analytic to SIEM and tune thresholds.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic requires implementation to identify high-volume exfiltration attempts.
  hunt_leads:
    - lead: Investigate sources initiating large HTTP/HTTPS POST requests to external domains exceeding 1GB.
      technique_id: T1567
      data_needed:
        - Nginx access logs
        - Web proxy logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The detection identifies anomalies where bytes out to a URL exceed 1GB in a 2-minute window.
---

## Overview
This detection identifies a high volume of outbound web traffic, specifically defined as more than 1GB of data sent to a URL within a 2-minute window. This behavior is considered an anomaly that may indicate unauthorized data exfiltration by malware or malicious insiders. The analytic utilizes the Web data model to monitor for these significant uploads.

## Impact
Confirmed malicious activity involving this volume of data transfer can lead to data breaches and the loss of sensitive organizational information.

## Recommendation
- Implement the monitoring analytic using the Web data model to track outbound byte sums per URL and source.
- Tune the 1GB/2-minute threshold to align with known organizational baselines and expected user behavior.
- Investigate triggers of this detection to determine if the transfer is legitimate or anomalous.
- Use the provided drilldown search to view associated risk events for the source IP over the last 7 days.
