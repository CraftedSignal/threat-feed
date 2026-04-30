---
title: MinIO Unauthenticated Object Write Vulnerability
slug: 2026-04-minio-auth-bypass
description: Two authentication bypass vulnerabilities in MinIO allow writing arbitrary objects to any bucket with only a valid access key, without the secret key or valid signature, impacting all MinIO deployments.
date: "2026-04-14T00:05:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - minio
  - authentication-bypass
  - object-storage
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-9c4q-hq6p-c237
  - https://github.com/minio/minio/commit/76913a9fd5c6e5c2dbd4e8c7faf56ed9e9e24091
  - https://min.io/aistor
rules:
  - title: Detect MinIO Unsigned Payload Trailer
    description: Detects requests using the STREAMING-UNSIGNED-PAYLOAD-TRAILER, indicative of potential exploitation of MinIO authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1550.004
    data_sources:
      - webserver
      - linux
  - title: Detect MinIO Snowball Auto Extract Exploit Attempt
    description: Detects attempts to exploit the missing signature verification in PutObjectExtractHandler by identifying requests with the Snowball auto-extract header.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1550.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

MinIO is susceptible to two authentication bypass vulnerabilities affecting all deployments up to AIStor RELEASE.2026-04-11T03-20-12Z. The vulnerability lies within the `STREAMING-UNSIGNED-PAYLOAD-TRAILER` code path. An attacker possessing a valid access key (including the default `minioadmin` or any key with WRITE permissions) can exploit these flaws to write arbitrary objects to any bucket. This bypass eliminates the need for the secret key or a valid cryptographic signature. One vulnerability involves missing signature verification in `PutObjectExtractHandler`, while the other bypasses signature verification using query-string credentials. These issues stem from the introduction of `authTypeStreamingUnsignedTrailer` support in commit 76913a9fd, specifically impacting releases from RELEASE.2023-05-18T00-05-36Z onwards.

## Attack Chain

1.  Attacker obtains a valid MinIO access key, either through default credentials or compromised accounts.
2.  For vulnerability 1, the attacker crafts a PUT request with `X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER`, `X-Amz-Meta-Snowball-Auto-Extract: true`, and an `Authorization` header containing the valid access key but a fabricated signature.
3.  The request is sent to the MinIO server's `PutObjectExtractHandler` endpoint.
4.  Due to the missing signature verification in the `PutObjectExtractHandler`, the request proceeds without proper authentication.
5.  The server extracts the access key and checks IAM permissions via `isPutActionAllowed`, but the fabricated signature is not validated.
6.  The server accepts the request, and the attacker-controlled payload is extracted into the target bucket.
7.  For vulnerability 2, the attacker crafts a PUT or PUT Part request omitting the `Authorization` header.
8.  The attacker includes authentication credentials (access key) exclusively via the `X-Amz-Credential` query parameter. Since the `Authorization` header is missing, signature verification is skipped, and the request proceeds with the permissions of the impersonated access key, allowing the attacker to write arbitrary objects.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized users to modify objects within MinIO storage buckets, potentially leading to data breaches, service disruptions, or the injection of malicious content. Any MinIO deployment is affected, creating a widespread risk for organizations relying on MinIO for their storage infrastructure. The CVSS v4.0 score of 8.8 (High) highlights the severity and potential impact of these vulnerabilities. The number of victims depends on the adoption rate of vulnerable MinIO versions.

## Recommendation

*   Upgrade to MinIO AIStor version `RELEASE.2026-04-11T03-20-12Z` or later, as indicated in the [MinIO AIStor documentation](https://docs.min.io/enterprise/aistor-object-store/upgrade-aistor-server/community-edition/).
*   Implement a block at the load balancer or reverse proxy to reject any requests containing `X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER`, as mentioned in the **Workarounds** section.
*   Deploy the Sigma rule `Detect MinIO Unsigned Payload Trailer` to identify exploitation attempts based on the presence of the vulnerable header.
*   Review and restrict WRITE permissions (`s3:PutObject`) to trusted principals to reduce the attack surface as described in the **Workarounds** section.
