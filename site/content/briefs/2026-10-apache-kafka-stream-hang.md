---
brief_id: brief-2026-10-28-apache-kafka-stream-hang
event_id: brief-2026-10-28-apache-kafka-stream-hang
revision: 1
activity_at: "2026-10-28T18:21:27Z"
title: 'Apache Kafka: Kafka Streams denial of service via integer overflow (CVE-2026-111496)'
slug: 2026-10-apache-kafka-stream-hang
description: An integer overflow vulnerability in Apache Kafka Streams allows an attacker to cause a StreamThread hang by supplying a record with a near-maximum timestamp.
date: "2026-10-28T18:21:27Z"
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
  validation_status: verified against oss-security advisory
cpes:
  - cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Kafka Streams (1.1.0-4.1.2, 4.2.0-4.2.1, 4.3.0-4.3.1)
cves:
  - id: CVE-2026-111496
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/421
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium
      action: Upgrade Apache Kafka Streams to the version specified in the vendor patch advisory
      owner: IT Operations
      addresses: CVE-2026-111496
      evidence: An integer overflow vulnerability exists in the PunctuationSchedule.next() function of Apache Kafka Streams.
---

Apache Kafka Streams contains an integer overflow vulnerability in the PunctuationSchedule.next() method. The application fails to perform bounds checking when calculating the next punctuation time using record timestamps. An attacker can supply a record with a timestamp near Long.MAX_VALUE to trigger the overflow, causing the affected StreamThread to hang.

## Impact

Successful exploitation leads to a denial of service condition for the specific stream processing application, as the affected StreamThread stops processing data.

## Recommendation

Identify and upgrade vulnerable Kafka Streams deployments to versions that include the fix for CVE-2026-111496. Refer to the official Apache Kafka security advisory for the specific corrected version releases.
