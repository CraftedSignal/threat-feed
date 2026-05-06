---
title: basic-ftp Client-Side Denial of Service via Malicious FTP Server
slug: 2024-01-basic-ftp-dos
description: The basic-ftp library is vulnerable to a client-side denial of service. A malicious FTP server can send an unterminated multiline response during the initial FTP banner phase, before authentication, causing the client to buffer attacker-controlled data without limit.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - ftp
  - denial-of-service
  - client-side
vendors:
  - patrickjuchli
products:
  - basic-ftp (<= 5.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-rpmf-866q-6p89
rules:
  - title: Detect Basic-ftp Unbounded Buffer DoS
    description: Detects connections to FTP servers sending excessive data before authentication, potentially indicating an attempt to exploit the basic-ftp unbounded buffer DoS vulnerability.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Excessive Memory Usage by Node.js Process
    description: Detects a Node.js process, potentially running basic-ftp, exhibiting high memory usage which could indicate a denial-of-service condition.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `basic-ftp` library, versions 5.3.0 and earlier, is susceptible to a client-side denial-of-service (DoS) attack. A malicious or compromised FTP server can exploit this vulnerability by sending an unterminated multiline response during the initial FTP banner exchange. This occurs before authentication, allowing the attacker to control the data being buffered by the client. The vulnerable client continuously appends attacker-controlled data to `FtpContext._partialResponse` and repeatedly reparses the growing buffer without enforcing a maximum size limit. This can lead to excessive memory consumption and CPU usage on the client-side, ultimately resulting in process-level DoS, container OOM kills, worker restarts, queue backlogs, or service degradation in applications that rely on automated FTP connections. The vulnerability was reported in May 2026.

## Attack Chain

1.  A victim application initiates an FTP connection to a server using the `basic-ftp` library.
2.  The attacker, controlling the FTP server, sends an initial FTP banner that starts a multiline response (e.g., "220-malicious banner starts").
3.  The attacker intentionally omits the terminating line of the multiline response (e.g., "220 ready").
4.  The `basic-ftp` library's `_onControlSocketData` function receives the initial chunk of data.
5.  The `_onControlSocketData` function concatenates the received chunk with the existing `_partialResponse`.
6.  The `parseControlResponse` function parses the complete response, identifies it as an incomplete multiline response, and returns the entire accumulated data as `rest`.
7.  The `_partialResponse` is updated with the `rest` value, storing the unterminated multiline data.
8.  The process repeats indefinitely with each new chunk of data, causing the `_partialResponse` to grow without bound, leading to memory exhaustion and DoS.

## Impact

Successful exploitation of this vulnerability can result in significant disruptions to applications that utilize the `basic-ftp` library. Observed damage includes Node.js process memory exhaustion, container OOM kills, worker crashes or restart loops, event loop CPU pressure due to repeated parsing, stuck FTP jobs, queue backlogs in scheduled import/export systems, and degraded availability of services relying on automated FTP ingestion. This can affect a wide range of applications including SaaS applications, backend jobs, document ingestion pipelines, legacy integrations, and build/deployment pipelines.

## Recommendation

*   Implement the provided Sigma rule `Detect Basic-ftp Unbounded Buffer DoS` to detect connections to FTP servers sending excessive data before authentication.
*   Upgrade to a patched version of `basic-ftp` that includes a maximum control response buffer size to address CVE-2026-44240.
*   Configure network monitoring to detect unusually large FTP banner responses based on the `network_connection` log source, which may indicate a malicious FTP server.
*   Implement application-level monitoring to track the memory usage of Node.js processes using `basic-ftp` to identify potential memory exhaustion issues.
