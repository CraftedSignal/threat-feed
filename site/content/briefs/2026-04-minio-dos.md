---
title: MinIO S3 Select CSV Parsing Denial of Service
slug: 2026-04-minio-dos
description: MinIO's S3 Select feature is vulnerable to denial of service due to unbounded memory allocation when processing CSV files without newlines, leading to memory exhaustion and server crashes.
date: "2026-04-09T17:32:31Z"
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

MinIO, an open-source object storage server, is susceptible to a denial-of-service (DoS) vulnerability within its S3 Select functionality. This flaw, present since the introduction of S3 Select support in commit 7c14cdb60e53dbfdad2be644dfb180cab19fffa7 (included in releases since RELEASE.2018-08-18T03-49-57Z), stems from unbounded memory allocation when parsing CSV files. Any authenticated user possessing both `s3:PutObject` and `s3:GetObject` permissions can exploit this vulnerability by…
