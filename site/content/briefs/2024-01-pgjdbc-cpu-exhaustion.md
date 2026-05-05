---
title: pgjdbc SCRAM Authentication CPU Exhaustion DoS
slug: 2024-01-pgjdbc-cpu-exhaustion
description: pgjdbc is vulnerable to a client-side denial of service during SCRAM-SHA-256 authentication, where a malicious server can instruct the driver to perform SCRAM authentication with a very large iteration count, leading to CPU exhaustion.
date: "2026-05-05T20:09:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dos
  - cpu_exhaustion
  - pgjdbc
  - scram
  - authentication
vendors:
  - PostgreSQL
products:
  - postgresql/pgjdbc (>= 42.2.0, < 42.7.11)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-42198
    cvss: 7.5
    epss: 0.00025
references:
  - https://github.com/advisories/GHSA-98qh-xjc8-98pq
rules:
  - title: Detect pgjdbc Excessive PBKDF2 Iteration Count
    description: Detects connections using pgjdbc with an unusually high SCRAM PBKDF2 iteration count, potentially indicating an attempt to exploit CVE-2026-42198.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious PostgreSQL Connection Strings
    description: Detects process creation events where the command line contains a PostgreSQL connection string with SCRAM authentication, potentially indicating an attempt to manipulate the connection.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The pgjdbc driver is susceptible to a denial-of-service (DoS) attack stemming from unbounded PBKDF2 iterations during SCRAM-SHA-256 authentication. A malicious PostgreSQL server can exploit this vulnerability by sending a `server-first-message` containing an excessively large SCRAM PBKDF2 iteration count to the client. This causes the client to expend an unbounded amount of CPU time executing the PBKDF2 algorithm, effectively tying up a CPU core. Repeated or concurrent attempts can exhaust client CPU resources, potentially wedging connection pools.  The vulnerability is present in pgjdbc versions 42.2.0 up to 42.7.10.  Successful exploitation does not lead to authentication bypass or password disclosure. The patch introduces `scramMaxIterations` to prevent excessive iterations.

## Attack Chain

1.  The application initiates a connection to a PostgreSQL server using the pgjdbc driver. The connection is configured to use SCRAM-SHA-256 authentication.
2.  The attacker compromises a PostgreSQL server or sets up a malicious server designed to exploit the pgjdbc vulnerability.
3.  The client attempts to authenticate with the malicious PostgreSQL server.
4.  The server responds with a `server-first-message` that specifies an extremely high PBKDF2 iteration count.
5.  The pgjdbc driver, prior to version 42.7.11, initiates the PBKDF2 computation using the attacker-supplied iteration count.
6.  The PBKDF2 computation consumes an excessive amount of CPU time on the client machine, potentially tying up a CPU core.
7.  If multiple connection attempts are made concurrently, or if connection retries are enabled, the CPU exhaustion can escalate rapidly.
8.  The client application becomes unresponsive or experiences significant performance degradation due to CPU exhaustion, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition on the client-side. Applications using vulnerable versions of pgjdbc may become unresponsive or experience significant performance degradation due to excessive CPU consumption. The impact is more pronounced in applications that allow users to supply their own database connection details or that connect through untrusted proxies.  While the source mentions a high severity, it does NOT appear that any large-scale attacks have leveraged this vulnerability.

## Recommendation

*   Upgrade to pgjdbc version 42.7.11 or later to incorporate the fix that introduces the `scramMaxIterations` connection property.
*   Configure the `scramMaxIterations` connection property to a reasonable value (e.g., 100,000) to prevent excessive PBKDF2 iterations.
*   Where possible, only connect to trusted PostgreSQL servers whose identity is verified using TLS with `sslmode=verify-full` and a trusted CA.
*   Deploy the Sigma rule "Detect pgjdbc Excessive PBKDF2 Iteration Count" to identify connections attempting to use unusually high SCRAM iteration counts.
*   Avoid relying solely on `loginTimeout` as a complete mitigation, as the worker thread may continue consuming CPU even after the timeout expires.
*   Implement operational measures such as limiting parallel connection attempts, adding retry backoff, and applying CPU or container limits to reduce the blast radius.
