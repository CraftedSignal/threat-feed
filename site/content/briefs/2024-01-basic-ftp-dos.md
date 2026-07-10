---
title: basic-ftp Denial-of-Service Vulnerability via Unbounded Memory Consumption
slug: 2024-01-basic-ftp-dos
description: The basic-ftp npm package version 5.2.2 and earlier is vulnerable to a denial-of-service attack. A malicious FTP server can send an extremely large or never-ending directory listing in response to the Client.list() command, causing the client to consume excessive memory until the process becomes unstable or crashes due to unbounded memory growth in the StringWriter class.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - ftp
  - memory-exhaustion
  - npm
vendors:
  - basic-ftp
products:
  - basic-ftp
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-rp42-5vxx-qpwr
rules:
  - title: Detect basic-ftp StringWriter Memory Exhaustion
    description: Detects processes that are likely vulnerable to basic-ftp's unbounded memory consumption in the StringWriter class by monitoring memory usage associated with node processes running basic-ftp.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect basic-ftp StringWriter Memory Exhaustion (Windows)
    description: Detects processes that are likely vulnerable to basic-ftp's unbounded memory consumption in the StringWriter class by monitoring memory usage associated with node processes running basic-ftp.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `basic-ftp` npm package, specifically version 5.2.2 and earlier, is susceptible to a denial-of-service (DoS) vulnerability. This vulnerability arises when the package is used to list directories from a remote FTP server. A malicious or compromised FTP server can exploit this by sending an excessively large or unending directory listing in response to the `Client.list()` command. The `basic-ftp` client, upon receiving this malicious response, attempts to buffer the entire listing in memory using the `StringWriter` class. The `StringWriter` class lacks any size limitations, resulting in unbounded memory growth as it concatenates incoming data chunks. This sustained memory allocation eventually leads to process instability and, ultimately, a crash of the application or service utilizing the vulnerable `basic-ftp` package. The vulnerability stems from the package's default directory listing flow within `dist/Client.js`, where the full listing response is downloaded into a `StringWriter` before parsing, as well as the unlimited buffering capability of `dist/StringWriter.js`.

## Attack Chain

1. An application using `basic-ftp` connects to an attacker-controlled or compromised FTP server.
2. The application initiates a directory listing request by calling the `client.list()` function.
3. The malicious FTP server responds with an extremely large or never-ending directory listing.
4. Within the `basic-ftp` library, the `_requestListWithCommand` function in `dist/Client.js` is invoked.
5. The `downloadTo` function in `transfer_1.js` starts downloading the listing response to a `StringWriter` instance.
6. The `StringWriter` class, in `dist/StringWriter.js`, receives chunks of data from the listing response.
7. The `_write` method of `StringWriter` concatenates each chunk to an in-memory `Buffer` without any size checks, leading to unbounded memory consumption via `this.buf = Buffer.concat([this.buf, chunk])`.
8. The excessive memory allocation causes the application's process to become unstable and eventually crash due to memory exhaustion.

## Impact

This vulnerability allows a malicious actor to perform a denial-of-service attack against applications and services that rely on the `basic-ftp` package to interact with FTP servers. The attack is triggered when the application connects to a malicious FTP server and attempts to list a directory. Successful exploitation leads to excessive memory consumption, resulting in process instability and potential termination of the application. This can disrupt services, cause data unavailability, and negatively impact overall system reliability. The impact is primarily targeted at services using the vulnerable `basic-ftp@5.2.2` against untrusted FTP endpoints.

## Recommendation

*   Implement application-level checks to monitor memory usage and restart processes exceeding acceptable thresholds (reference: Impact section).
*   Deploy the Sigma rule `Detect basic-ftp StringWriter Memory Exhaustion` to identify processes using `basic-ftp` that are allocating large amounts of memory (reference: rules section).
*   Upgrade to a patched version of `basic-ftp` that includes a fix for the unbounded memory consumption issue.
*   Implement a maximum listing size within your application, aborting transfers that exceed the configured limit, as suggested in the advisory's remediation section.
