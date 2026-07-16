---
title: ArcadeDB IMPORT DATABASE Allows SSRF and Arbitrary Local File Read
slug: 2026-07-arcadedb-ssrf-file-read
description: Authenticated users can exploit an unvalidated `IMPORT DATABASE` function in ArcadeDB (CVE-2026-54077) to perform Server-Side Request Forgery (CWE-918) against cloud metadata endpoints and internal services, or achieve arbitrary local file read (CWE-22) via `file://` paths, exposing sensitive data.
date: "2026-07-16T20:07:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arcadedb
  - ssrf
  - file-read
  - cve
  - database
vendors:
  - ArcadeData
products:
  - arcadedb-engine (< 26.6.1)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: read local files reachable by the server process (e.g. `/etc/passwd`, credential files) by importing `file://` paths, exposing their contents as records.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: cause the server to issue HTTP(S) requests to arbitrary destinations, including [...] internal-only services, and ingest the responses as queryable records.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: cause the server to issue HTTP(S) requests to arbitrary destinations, including cloud metadata endpoints (e.g. `169.254.169.254`) and ingest the responses as queryable records.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8w86-m9h8-hvqg
  - https://github.com/ArcadeData/arcadedb/pull/4422
rules:
  - title: Detects CVE-2026-54077 Exploitation - ArcadeDB SSRF to Cloud Metadata
    description: Detects outbound network connections from the ArcadeDB server process to known cloud metadata IP addresses (e.g., 169.254.169.254), indicative of CVE-2026-54077 exploitation via SSRF.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1592.002
    data_sources:
      - network_connection
      - linux
  - title: Detects CVE-2026-54077 Exploitation - ArcadeDB Local Sensitive File Read
    description: Detects file read events by the ArcadeDB server process targeting sensitive system files (e.g., /etc/passwd, /etc/shadow), which can occur during CVE-2026-54077 exploitation via arbitrary local file read.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1005
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A high-severity vulnerability (CVE-2026-54077) in ArcadeDB versions prior to 26.6.1 allows authenticated users to perform Server-Side Request Forgery (SSRF) and arbitrary local file reads. The flaw exists in the `IMPORT DATABASE` SQL statement, which did not require administrative privileges and failed to validate the source URL provided to its importer. This allows any authenticated user with SQL command access, not just root or administrators, to force the ArcadeDB server to make HTTP(S) requests to arbitrary internal and external destinations, including cloud metadata endpoints (e.g., `169.254.169.254`). Attackers can also leverage `file://` paths to read sensitive local files, such as `/etc/passwd` or credential files, which are then ingested as queryable database records. The issue is critical as it enables information disclosure, internal network reconnaissance, and potential lateral movement from a compromised authenticated user account within an ArcadeDB deployment.

## Attack Chain

1. An authenticated user with SQL command access connects to the ArcadeDB server's SQL command/query endpoints (`/api/v1/command`, `/api/v1/query`).
2. The user crafts and executes an `IMPORT DATABASE` SQL statement specifying a target URL or file path.
3. To achieve Server-Side Request Forgery (SSRF), the user provides an HTTP(S) URL pointing to an internal service or a cloud metadata endpoint (e.g., `http://169.254.169.254/latest/meta-data/`).
4. The ArcadeDB server executes the `IMPORT DATABASE` statement, making an unvalidated outbound HTTP(S) request to the specified URL.
5. The server ingests the HTTP response content from the internal service or cloud metadata endpoint into a database record, allowing the attacker to query the retrieved information.
6. Alternatively, to achieve arbitrary local file read, the user provides a `file://` path to a sensitive system file (e.g., `file:///etc/passwd`, `/etc/shadow`, or credential files).
7. The ArcadeDB server executes the `IMPORT DATABASE` statement, attempting to read the local file without proper path validation.
8. The server ingests the file's content into a database record, enabling the authenticated attacker to retrieve and view the sensitive data.

## Impact

Successful exploitation of CVE-2026-54077 allows authenticated users to bypass security controls, gaining unauthorized access to internal network resources and sensitive local files residing on the ArcadeDB server. This can lead to significant information disclosure, including cloud instance metadata, internal service configurations, and system-level credentials. Any organization using vulnerable versions of ArcadeDB is at risk, particularly if untrusted users have SQL query access or if the server is deployed in an environment with access to sensitive internal networks or cloud APIs. The consequences of this data exposure could include unauthorized data exfiltration, lateral movement within the network, or further exploitation of exposed internal services.

## Recommendation

* Patch CVE-2026-54077 by upgrading ArcadeDB to version `26.6.1` or later immediately.
* Restrict SQL command/query access in ArcadeDB to only trusted administrative users, as specified in the workarounds section of the advisory.
* Deploy the provided Sigma rules to your SIEM and tune them for your environment, especially regarding the specific process identity of your ArcadeDB instance, to detect suspicious network connections and file access.
