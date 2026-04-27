---
title: MinIO SSE Metadata Injection via Replication Headers Leads to Data Unreadability
slug: 2024-05-minio-metadata-injection
description: A vulnerability in MinIO allows authenticated users with `s3:PutObject` permission to inject internal server-side encryption metadata into objects via crafted replication headers, leading to permanent data unreadability.
date: "2026-03-27T22:26:05Z"
severities:
  - high
tags:
  - minio
  - s3
  - metadata-injection
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-3rh2-v3gr-35p9
  - https://github.com/minio/minio/pull/19107
  - https://min.io/aistor
rules:
  - title: Detect PutObject Request with Replication Headers Without Source Replication Request
    description: Detects PutObject requests containing X-Minio-Replication-Server-Side-Encryption headers but lacking the X-Minio-Source-Replication-Request header, indicating potential metadata injection.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect PutObject Request with X-Minio-Internal-Server-Side-Encryption Headers
    description: Detects PutObject requests containing X-Minio-Internal-Server-Side-Encryption headers, which should not be present in external requests, potentially indicating unauthorized header injection.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A flaw in MinIO's `extractMetadataFromMime()` function allows any authenticated user with `s3:PutObject` permission to inject internal server-side encryption (SSE) metadata into objects. This is achieved by sending crafted `X-Minio-Replication-*` headers on a normal PutObject request. The MinIO server incorrectly maps these headers to `X-Minio-Internal-*` encryption metadata without validating if the request is a legitimate replication request. Objects written in this manner contain bogus…
