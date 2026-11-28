---
brief_id: brief-2026-11-28-gcp-storage-new-ip
event_id: brief-2026-11-28-gcp-storage-new-ip
revision: 1
activity_at: "2026-11-28T20:50:22Z"
title: 'Google Cloud Platform: Detecting GCP Storage bucket access from new IP addresses'
slug: 2026-11-gcp-storage-new-ip
description: This analytic identifies access to GCP Storage buckets from IP addresses not present in a historical lookup table of previously seen access events.
date: "2026-11-28T20:50:22Z"
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
  likelihood: roughly even chance
vendors:
  - Google
products:
  - GCP Storage
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: This activity is significant as it may indicate unauthorized access or potential reconnaissance by an attacker.
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_gcp_storage_access_from_a_new_ip.yml
action_plan:
  hunt_leads:
    - lead: Identify successful GCP Storage bucket access events (HTTP 200) originating from IP addresses not present in the historical lookup table of known-good access, specifically looking for new activity observed within the last 70 minutes.
      technique_id: T1530
      data_needed:
        - GCP Storage bucket-access logs via Cloud Pub/Sub
        - previously_seen_gcp_storage_access_from_remote_ip lookup table
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This activity is significant as it may indicate unauthorized access or potential reconnaissance by an attacker. If confirmed malicious, this could lead to data exfiltration, unauthorized data manipulation, or further compromise of the GCP environment.
---

## Overview
The detection identifies access to GCP Storage buckets from new or previously unseen remote IP addresses. The analytic utilizes GCP Storage bucket-access logs ingested via Cloud Pub/Sub and compares current access events against a lookup table of previously seen IP addresses to detect new connections. This activity may indicate unauthorized access or reconnaissance.

## Attack Chain
The detection relies on the collection of storage bucket access logs, which are processed through GCP Cloud Pub/Sub and subsequently analyzed within the Splunk environment to identify new IP sources. This fits within the Data from Cloud Storage (T1530) technique.

## Impact
If confirmed malicious, this activity could lead to data exfiltration, unauthorized data manipulation, or further compromise of the GCP environment.

## Recommendation
To implement this detection, configure the Splunk Add-on for Google Cloud Platform to ingest GCP Pub/Sub logs and enable storage bucket logging. It is recommended to run the associated correlation search on an hourly basis, 30 minutes past the hour. Tuning is required to mitigate false positives, as GCP Storage buckets can be accessed by any IP if ACLs are configured to allow it.
