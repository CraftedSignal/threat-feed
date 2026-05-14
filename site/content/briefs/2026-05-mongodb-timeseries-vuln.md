---
title: MongoDB Timeseries Collection Vulnerability (CVE-2026-8053)
slug: 2026-05-mongodb-timeseries-vuln
description: MongoDB published a security advisory to address CVE-2026-8053, an undefined behavior vulnerability when inserting data with duplicate field names into timeseries collections, affecting versions 5.0.0 through 8.3.1.
date: "2026-05-14T15:49:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - mongodb
  - cve-2026-8053
  - timeseries
  - denial of service
vendors:
  - MongoDB
products:
  - MongoDB 8.3.0
  - MongoDB 8.3.1
  - MongoDB 8.2.0
  - MongoDB 8.2.8
  - MongoDB 8.0.0
  - MongoDB 8.0.22
  - MongoDB 7.0.0
  - MongoDB 7.0.33
  - MongoDB 6.0.0
  - MongoDB 6.0.27
  - MongoDB 5.0.0
  - MongoDB 5.0.32
cves:
  - id: CVE-2026-8053
    cvss: 8.8
    epss: 0.00064
references:
  - https://cyber.gc.ca/en/alerts-advisories/mongodb-security-advisory-av26-468
  - https://jira.mongodb.org/browse/SERVER-126021
rules:
  - title: Detect MongoDB Insert with Duplicate Field Names in Timeseries
    description: Detects CVE-2026-8053 exploitation — Attempts to insert documents with duplicate field names into MongoDB timeseries collections, potentially leading to denial of service or data corruption.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - database
      - mongodb
rules_count: 1
---

On May 12, 2026, MongoDB released a security advisory addressing CVE-2026-8053. This vulnerability impacts MongoDB versions 5.0.0 to 5.0.32, 6.0.0 to 6.0.27, 7.0.0 to 7.0.33, 8.0.0 to 8.0.22, 8.2.0 to 8.2.8, and 8.3.0 to 8.3.1. The vulnerability stems from undefined behavior when handling data insertion with duplicate field names into timeseries collections. Successful exploitation could lead to denial of service or unexpected data corruption. Defenders should apply the necessary updates as soon as possible.

## Attack Chain

1. An attacker crafts a malicious document containing duplicate field names specifically designed to trigger the vulnerability in timeseries collections.
2. The attacker connects to the MongoDB server.
3. The attacker authenticates (or exploits an authentication bypass vulnerability, if present).
4. The attacker targets a specific timeseries collection within the database.
5. The attacker executes an `insert` operation with the crafted malicious document.
6. The MongoDB server attempts to process the insertion, triggering the undefined behavior due to the duplicate field names.
7. This undefined behavior can manifest as a denial of service, causing the MongoDB server to crash or become unresponsive.
8. Alternatively, the vulnerability can lead to data corruption within the timeseries collection, compromising data integrity.

## Impact

Successful exploitation of CVE-2026-8053 can lead to a denial-of-service condition, disrupting database availability. Data corruption within timeseries collections could also occur, leading to loss of data integrity and potentially impacting applications that rely on accurate data from these collections. The number of affected MongoDB instances is currently unknown, but any instance running a vulnerable version and utilizing timeseries collections is susceptible.

## Recommendation

*   Upgrade MongoDB instances to a patched version outside the ranges specified (8.3.0 to 8.3.1, 8.2.0 to 8.2.8, 8.0.0 to 8.0.22, 7.0.0 to 7.0.33, 6.0.0 to 6.0.27, and 5.0.0 to 5.0.32) to remediate CVE-2026-8053, as recommended in the advisory.
*   Deploy the Sigma rule to detect potentially malicious database insertions targeting timeseries collections.
