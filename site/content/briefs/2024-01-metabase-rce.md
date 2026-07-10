---
title: Metabase Enterprise Remote Code Execution via Serialization Import
slug: 2024-01-metabase-rce
description: Authenticated administrators in vulnerable Metabase Enterprise editions can achieve Remote Code Execution (RCE) and Arbitrary File Read by injecting an `INIT` property into the H2 JDBC spec via a crafted serialization archive through the `POST /api/ee/serialization/import` endpoint.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - metabase
  - rce
  - serialization
  - cve-2026-33725
vendors:
  - Metabase
products:
  - Metabase Enterprise
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33725
rules:
  - title: Detect Metabase Enterprise Serialization Import Attempt
    description: Detects attempts to exploit CVE-2026-33725 by monitoring requests to the /api/ee/serialization/import endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Metabase Enterprise Database Sync with INIT Property
    description: Detects suspicious database sync operations potentially related to exploitation of CVE-2026-33725 by monitoring for the `INIT` property.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Metabase is a widely used open-source business intelligence and analytics tool. A critical vulnerability, CVE-2026-33725, affects Metabase Enterprise Edition versions prior to 1.54.22, 1.55.22, 1.56.22, 1.57.16, 1.58.10, and 1.59.4. This flaw allows authenticated administrators to execute arbitrary code and read arbitrary files. The vulnerability stems from the `POST /api/ee/serialization/import` endpoint, which can be exploited by injecting a malicious `INIT` property into the H2 JDBC specification within a crafted serialization archive. This injected property enables the execution of arbitrary SQL commands during a database synchronization process. The vulnerability has been confirmed to be exploitable on Metabase Cloud, highlighting the broad impact of this issue. Only Metabase Enterprise is affected, as the OSS version lacks the vulnerable code paths.

## Attack Chain

1. An attacker authenticates as an administrator to a vulnerable Metabase Enterprise instance.
2. The attacker crafts a malicious serialization archive containing an injected `INIT` property within the H2 JDBC spec.
3. The malicious archive is submitted to the `/api/ee/serialization/import` endpoint via a POST request.
4. Metabase processes the archive, triggering the H2 JDBC driver with the injected `INIT` property.
5. The `INIT` property executes arbitrary SQL commands during a database synchronization operation.
6. The attacker gains the ability to execute arbitrary code on the server hosting the Metabase instance.
7. The attacker leverages the code execution to read arbitrary files on the system.
8. The attacker may use this access to exfiltrate sensitive data, pivot to other systems, or disrupt services.

## Impact

Successful exploitation of CVE-2026-33725 allows attackers to gain complete control over affected Metabase Enterprise instances, potentially leading to data breaches, service disruption, and lateral movement within the network. The vulnerability affects all versions of Metabase Enterprise that have serialization, dating back to at least version 1.47, before being patched in versions 1.54.22, 1.55.22, 1.56.22, 1.57.16, 1.58.10, and 1.59.4. Given the widespread use of Metabase for business intelligence, a successful attack can expose sensitive business data.

## Recommendation

*   Upgrade Metabase Enterprise instances to versions 1.54.22, 1.55.22, 1.56.22, 1.57.16, 1.58.10, 1.59.4, or later to patch CVE-2026-33725.
*   As a temporary workaround, disable the serialization import endpoint in the Metabase instance, as recommended in the overview, to prevent access to the vulnerable code paths.
*   Deploy the Sigma rule "Detect Metabase Enterprise Serialization Import Attempt" to monitor for attempts to exploit the vulnerability via the `/api/ee/serialization/import` endpoint.
