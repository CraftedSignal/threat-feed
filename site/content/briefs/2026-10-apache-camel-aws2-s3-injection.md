---
brief_id: brief-2026-10-23-apache-camel-aws2-s3-injection
event_id: brief-2026-10-23-apache-camel-aws2-s3-injection
revision: 1
activity_at: "2026-10-23T14:58:01Z"
title: 'Apache Camel: Expression Language Injection in Camel-AWS2-S3 (CVE-2026-95664)'
slug: 2026-10-apache-camel-aws2-s3-injection
description: The Apache Camel AWS2-S3 component is vulnerable to Expression Language Injection. The Camel-AWS2-S3 producer evaluates untrusted S3 object keys from the CamelAwsS3Key header as Simple expressions.
date: "2026-10-23T14:58:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
products:
  - org.apache.camel:camel-aws2-s3 (4.8.0 before 4.18.5)
  - org.apache.camel:camel-aws2-s3 (4.19.0 before 4.22.2)
cves:
  - id: CVE-2026-95664
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/347
---

The Apache Camel AWS2-S3 component contains an "Improper Neutralization of Special Elements used in an Expression Language Statement" ('Expression Language Injection') vulnerability. The producer evaluates untrusted S3 object keys provided via the CamelAwsS3Key header as Simple expressions.
