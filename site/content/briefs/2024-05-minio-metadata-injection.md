---
title: MinIO SSE Metadata Injection via Replication Headers Leads to Data Unreadability
slug: 2024-05-minio-metadata-injection
description: A vulnerability in MinIO allows authenticated users with `s3:PutObject` permission to inject internal server-side encryption metadata into objects via crafted replication headers, leading to permanent data unreadability.
date: "2026-03-27T22:26:05Z"
type: coverage
types:
  - coverage
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

A flaw in MinIO's `extractMetadataFromMime()` function allows any authenticated user with `s3:PutObject` permission to inject internal server-side encryption (SSE) metadata into objects. This is achieved by sending crafted `X-Minio-Replication-*` headers on a normal PutObject request. The MinIO server incorrectly maps these headers to `X-Minio-Internal-*` encryption metadata without validating if the request is a legitimate replication request. Objects written in this manner contain bogus encryption keys and become permanently unreadable through the S3 API. This vulnerability affects all MinIO releases up to the final release of the `minio/minio` open-source project, specifically versions introduced after commit `468a9fae83e965ecefa1c1fdc2fc57b84ece95b0` (included in `RELEASE.2024-03-30T09-41-56Z`). It was resolved in MinIO AIStor `RELEASE.2026-03-26T21-24-40Z`.

## Attack Chain

1. Attacker authenticates to the MinIO server with valid credentials having `s3:PutObject` permissions.
2. The attacker crafts a malicious PutObject request targeting a specific bucket and object key.
3. The attacker includes `X-Minio-Replication-Server-Side-Encryption-*` headers in the PutObject request.
4. The attacker omits the `X-Minio-Source-Replication-Request` header, which would normally indicate a legitimate replication request.
5. The MinIO server's `extractMetadataFromMime()` function incorrectly maps the crafted `X-Minio-Replication-*` headers to `X-Minio-Internal-Server-Side-Encryption-*` headers.
6. The server writes the object metadata, including the bogus encryption keys, to the object storage.
7. Subsequent GetObject or HeadObject requests for the modified object will fail because the server treats the object as encrypted with non-existent or incorrect keys.
8. The attacker achieves a targeted denial-of-service, rendering the object permanently unreadable via the S3 API.

## Impact

This vulnerability enables a targeted denial-of-service attack. An attacker can selectively corrupt individual objects or entire buckets within a MinIO deployment. Successful exploitation results in permanent data loss, as affected objects become unreadable through the S3 API. This can disrupt critical services relying on the object storage and potentially impact a large number of users if entire buckets are targeted.

## Recommendation

*   Upgrade to MinIO AIStor version `RELEASE.2026-03-26T21-24-40Z` or later to patch the vulnerability as documented in the [release notes](https://docs.min.io/enterprise/aistor-object-store/upgrade-aistor-server/community-edition/).
*   Implement a reverse proxy or load balancer rule to drop or reject any request containing `X-Minio-Replication-Server-Side-Encryption-*` headers that does not also include `X-Minio-Source-Replication-Request`, mitigating the injection path as described in the [Workarounds](#workarounds) section.
*   Review and restrict IAM policies to limit `s3:PutObject` grants to trusted principals only, reducing the attack surface as noted in the [Workarounds](#workarounds) section.
