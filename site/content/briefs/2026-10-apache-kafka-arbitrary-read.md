---
brief_id: brief-2026-10-28-apache-kafka-arbitrary-read
event_id: brief-2026-10-28-apache-kafka-arbitrary-read
revision: 1
activity_at: "2026-10-28T18:21:06Z"
title: 'Apache Kafka: Unauthorized arbitrary file and environment variable read (CVE-2026-112375)'
slug: 2026-10-apache-kafka-arbitrary-read
description: An authenticated principal in Apache Kafka can leverage crafted IncrementalAlterConfigs or AlterConfigs requests to perform arbitrary file and environment variable reads from the broker host.
date: "2026-10-28T18:21:06Z"
lastmod: "2026-10-28T18:22:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source confirmed vulnerability; patch availability pending.
cpes:
  - cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:kafka:3.7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:kafka:4.1.2:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:kafka:4.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:kafka:4.2.1:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:kafka:4.3.0:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - backend
  - cve-2026-83525
vendors:
  - Apache
products:
  - Kafka (3.2.0-4.1.2)
  - Kafka (4.2.0-4.2.1)
  - Kafka (4.3.0-4.3.1)
  - Kafka (3.7.0-4.1.2)
  - Kafka (4.3.0)
  - Kafka (2.8.0 <= version < 4.2.2)
  - Kafka (4.3.0 <= version < 4.3.2)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: An authenticated Kafka principal with no authorization grants (not even ALTER_CONFIGS) can make a broker read a file or an environment variable from the broker host and return its contents.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: An authenticated Kafka principal with no authorization grants (not even ALTER_CONFIGS) can make a broker read a file or an environment variable from the broker host and return its contents.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: ClientTelemetryUtils.decompress() then decompresses the payload with no limit on the decompressed output size, growing a broker out-of-memory denial of service
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: allows an authenticated attacker with CLUSTER_ACTION privilege to cause a denial of service (controller process termination) via a crafted FetchSnapshotRequest
    confidence_band: high
cves:
  - id: CVE-2026-112375
    kev_status: "false"
  - id: CVE-2026-111073
    kev_status: "false"
  - id: CVE-2026-83525
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/424
  - https://seclists.org/oss-sec/2026/q4/418
  - https://seclists.org/oss-sec/2026/q4/414
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Patch or upgrade Apache Kafka to the vendor-recommended secure version
      owner: IT Operations
      due: 72h
      evidence: Vulnerability in PushTelemetry API (CVE-2026-111073)
  hunt_leads:
    - lead: Search Kafka audit logs for AlterConfigs or IncrementalAlterConfigs requests directed at BROKER resources.
      data_needed:
        - Kafka Request Log / Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An IncrementalAlterConfigs (or AlterConfigs) request targeting a BROKER resource reaches the...
    - lead: Identify repeated broker crashes or OOM-Killer activity associated with Kafka process logs
      technique_id: T1499
      data_needed:
        - Broker logs
        - System dmesg/OOM-Killer logs
        - Kafka metrics
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The component grows memory uncontrollably during decompression causing a DoS
    - lead: Investigate KRaft controller logs for unexpected process crashes or recurring crashes following FetchSnapshotRequest handling.
      technique_id: T1498
      data_needed:
        - Kafka controller application logs
        - System daemon/service logs (e.g., systemd journal)
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: The flaw causes controller process termination.
  mitigation_plan:
    - priority: immediate
      action: Review and audit Kafka ACLs to restrict ALTER_CONFIGS permissions to authorized principals only.
      owner: IT Operations
      addresses: CVE-2026-112375
      evidence: An authenticated Kafka principal with no authorization grants (not even ALTER_CONFIGS) can make a broker read a file or an environment variable...
    - priority: immediate
      action: Apply patch for CVE-2026-111073
      owner: IT Operations
      addresses: CVE-2026-111073
      evidence: Vulnerability in Kafka PushTelemetry API
    - priority: immediate
      action: Upgrade Apache Kafka to 4.2.2 or 4.3.2
      owner: IT Operations
      addresses: CVE-2026-83525
      evidence: Source advisory recommends versions 4.2.2 and 4.3.2 for remediation.
updates:
  - at: "2026-10-28T18:21:47Z"
    level: L2
    summary: added coverage for Kafka (3.7.0-4.1.2) +2 products
    sources:
      - oss-security
    source_urls:
      - https://seclists.org/oss-sec/2026/q4/418
  - at: "2026-10-28T18:22:08Z"
    level: L2
    summary: added coverage for Kafka (2.8.0 <= version < 4.2.2) +1 products
    sources:
      - oss-security
    source_urls:
      - https://seclists.org/oss-sec/2026/q4/414
---

Apache Kafka is vulnerable to an information disclosure flaw (CVE-2026-112375) where an authenticated principal, even without 'ALTER_CONFIGS' permissions, can induce a broker to read arbitrary files and environment variables from the host filesystem. The vulnerability is triggered by sending a specially crafted 'IncrementalAlterConfigs' or 'AlterConfigs' request targeting a 'BROKER' resource. 

## Impact

Successful exploitation allows an authenticated principal to retrieve sensitive information from the broker host, including configuration files, credentials, or environment variables containing secrets.

## Recommendation

- Upgrade to a patched version of Apache Kafka once available.
- Review Kafka ACLs to ensure minimal privilege for all principals and restrict access to the 'IncrementalAlterConfigs' and 'AlterConfigs' operations.
- Monitor Kafka logs for unusual 'IncrementalAlterConfigs' or 'AlterConfigs' requests targeting 'BROKER' resources from unauthorized principals.
