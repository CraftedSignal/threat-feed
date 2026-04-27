---
title: MinIO Unauthenticated Object Write Vulnerability
slug: 2026-04-minio-auth-bypass
description: Two authentication bypass vulnerabilities in MinIO allow writing arbitrary objects to any bucket with only a valid access key, without the secret key or valid signature, impacting all MinIO deployments.
date: "2026-04-14T00:05:52Z"
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

MinIO is susceptible to two authentication bypass vulnerabilities affecting all deployments up to AIStor RELEASE.2026-04-11T03-20-12Z. The vulnerability lies within the `STREAMING-UNSIGNED-PAYLOAD-TRAILER` code path. An attacker possessing a valid access key (including the default `minioadmin` or any key with WRITE permissions) can exploit these flaws to write arbitrary objects to any bucket. This bypass eliminates the need for the secret key or a valid cryptographic signature. One…
