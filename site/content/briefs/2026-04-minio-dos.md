---
title: MinIO S3 Select CSV Parsing Denial of Service
slug: 2026-04-minio-dos
description: MinIO's S3 Select feature is vulnerable to denial of service due to unbounded memory allocation when processing CSV files without newlines, leading to memory exhaustion and server crashes.
date: "2026-04-09T17:32:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dos
  - minio
  - s3select
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-h749-fxx7-pwpg
  - https://github.com/minio/minio/commit/7c14cdb60e53dbfdad2be644dfb180cab19fffa7
  - https://github.com/minio/minio/pull/8200
  - https://min.io/aistor
rules:
  - title: Detect MinIO S3 Select DoS Attempt via High Memory Usage
    description: Detects potential denial-of-service attempts against MinIO by monitoring for abnormally high memory usage associated with the MinIO process.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect MinIO S3 Select Requests
    description: Detects S3 Select requests which are required to trigger the vulnerability.
    platform: sigma
    severity: low
    tactics:
      - availability
      - initial_access
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

MinIO, an open-source object storage server, is susceptible to a denial-of-service (DoS) vulnerability within its S3 Select functionality. This flaw, present since the introduction of S3 Select support in commit 7c14cdb60e53dbfdad2be644dfb180cab19fffa7 (included in releases since RELEASE.2018-08-18T03-49-57Z), stems from unbounded memory allocation when parsing CSV files. Any authenticated user possessing both `s3:PutObject` and `s3:GetObject` permissions can exploit this vulnerability by uploading a specially crafted CSV file lacking newline characters. A relatively small, gzip-compressed CSV file (around 2MB) can decompress into gigabytes of data, triggering excessive memory consumption and causing the MinIO server process to crash. Defenders should upgrade to MinIO AIStor RELEASE.2025-12-20T04-58-37Z or later.

## Attack Chain

1. An attacker authenticates to the MinIO server with valid credentials, having both `s3:PutObject` and `s3:GetObject` permissions.
2. The attacker crafts a malicious CSV file. This file intentionally lacks newline characters and may be compressed using gzip to maximize its impact.
3. The attacker uploads the malicious CSV file to a MinIO bucket using the `s3:PutObject` permission.
4. The attacker then sends an S3 Select `GetObject` request to the MinIO server, specifying the malicious CSV file as the target. This triggers the vulnerable CSV parsing logic.
5. The `nextSplit()` function in `internal/s3select/csv/reader.go` attempts to read the CSV file line by line, using `bufio.Reader.ReadBytes('\n')`.
6. Due to the absence of newline characters, the function reads the entire file into memory without any size limitation, leading to unbounded memory allocation.
7. The excessive memory consumption leads to an out-of-memory (OOM) condition on the MinIO server.
8. The MinIO server process crashes, resulting in a denial of service for all users.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering the MinIO server unavailable. The attacker can repeatedly trigger the vulnerability, causing prolonged disruption to the service. The vulnerability affects all MinIO deployments using versions RELEASE.2018-08-18T03-49-57Z up to RELEASE.2025-12-03T08-12-39Z. The number of affected installations is unknown. Sectors using MinIO for object storage are vulnerable. If successful, this attack could interrupt services reliant on the object storage.

## Recommendation

*   Upgrade to MinIO AIStor version RELEASE.2025-12-20T04-58-37Z or later to remediate the vulnerability as documented in the advisory.
*   If upgrading is not immediately feasible, disable S3 Select access via IAM policies, specifically denying `s3:GetObject` actions or `SelectObjectContent` requests as described in the "Workarounds" section of the advisory.
*   Monitor MinIO server resource consumption, particularly memory usage, to detect potential exploitation attempts. Deploy the provided Sigma rule to detect potential DoS attempts.
