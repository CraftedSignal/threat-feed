---
brief_id: brief-2026-11-06-dga-ml-detection
event_id: brief-2026-11-06-dga-ml-detection
revision: 1
activity_at: "2026-11-06T21:01:37Z"
title: 'Elastic: Machine learning detection for DNS-based Domain Generation Algorithms'
slug: 2026-11-dga-ml-detection
description: This detection capability utilizes supervised machine learning to identify DNS queries with high DGA probability, a technique commonly used by malware to establish resilient command and control infrastructure.
date: "2026-11-06T21:01:37Z"
type: advisory
types:
  - advisory
severities:
  - low
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
  - dga
  - command-and-control
  - machine-learning
  - network-security
  - dns
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.004
    technique_name: DNS
    evidence: DGA is a common technique used by malware to establish resilient command and control network activity.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568.002
    technique_name: Domain Generation Algorithms
    evidence: A supervised machine learning model has identified a DNS question name with a high probability of sourcing from a Domain Generation Algorithm.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/dga
  - https://www.elastic.co/security-labs/detect-domain-generation-algorithm-activity-with-new-kibana-integration
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/dga/command_and_control_ml_dns_request_high_dga_probability.toml
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify high-probability DGA DNS requests in network telemetry
      technique_id: T1568.002
      data_needed:
        - DNS query logs
        - Network packet capture
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: ML models can flag DNS queries with high DGA probability, aiding in identifying potential malicious activity.
  mitigation_plan:
    - priority: medium
      action: Configure ML-based DGA detection integration in Kibana
      owner: Detection Engineering
      addresses: T1568.002
      evidence: The rule requires the Domain Generation Algorithm (DGA) Detection integration assets to be installed.
---

Elastic has released an updated machine learning-based detection rule designed to identify Domain Generation Algorithm (DGA) activity within DNS traffic. DGA is a technique used by various malware families to generate large pools of domain names dynamically, allowing them to cycle through C2 infrastructure and evade static blocklist defenses. The detection relies on a supervised ML model to calculate a malicious probability score for DNS question names.

## Impact

The use of DGA allows malware to maintain communication with C2 servers even if individual domains are blocked or sinkholed. Monitoring for these patterns helps in early detection of C2 beaconing before a full-scale compromise or data exfiltration occurs.

## Recommendation

- Deploy the "Domain Generation Algorithm Detection" integration via Kibana to enable the required ML framework and ingest pipelines.
- Ingest DNS logs from Elastic Defend, Network Packet Capture, or Packetbeat into the Elastic Security platform.
- Tune the detection logic by adding exclusions for known internal development tools, software update mechanisms, and CDNs that frequently exhibit DGA-like naming patterns.
- Investigate high-scoring alerts by pivoting to endpoint logs on the source host to check for suspicious process activity associated with the DNS request.
