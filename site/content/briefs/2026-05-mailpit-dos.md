---
title: Mailpit Unauthenticated Remote Memory Exhaustion DoS Vulnerability
slug: 2026-05-mailpit-dos
description: Mailpit is vulnerable to an unauthenticated remote memory-exhaustion denial-of-service attack due to missing size limits on incoming SMTP DATA and HTTP requests, leading to unbounded memory and disk growth, potentially crashing the application.
date: "2026-05-19T15:54:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - memory exhaustion
  - cve-2026-45713
  - mailpit
vendors:
  - axllent
products:
  - mailpit
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-fpxj-m5q8-fphw
  - https://github.com/axllent/mailpit/blob/develop/internal/smtpd/smtpd.go#L107
  - https://github.com/axllent/mailpit/blob/develop/internal/smtpd/smtpd.go#L863-L877
  - https://github.com/axllent/mailpit/blob/develop/internal/smtpd/main.go#L223-L248
  - https://github.com/axllent/mailpit/blob/develop/server/apiv1/send.go#L45-L52
rules:
  - title: Detect Mailpit Excessive SMTP Data
    description: Detects CVE-2026-45713 exploitation — Monitors for excessive data transfer during SMTP DATA command, indicating a potential memory exhaustion DoS attempt.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
  - title: Detect Mailpit Excessive HTTP API Send Payload
    description: Detects CVE-2026-45713 exploitation — Monitors for excessively large HTTP POST requests to the /api/v1/send endpoint, indicating a potential memory exhaustion DoS attempt.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect Mailpit High Memory Usage
    description: Detects Mailpit using excessive memory, indicating a potential DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Mailpit is susceptible to an unauthenticated remote denial-of-service (DoS) attack due to the absence of input size validation for SMTP DATA payloads and HTTP requests to the `/api/v1/send` endpoint. Specifically, the `Server.MaxSize` field in the Mailpit SMTP server, intended to control the maximum allowed DATA payload size, is never assigned a value, effectively disabling the size limit. Similarly, the HTTP endpoint lacks `http.MaxBytesReader`, resulting in unbounded memory allocation when processing requests. This vulnerability allows a network-reachable attacker to exhaust server memory by sending arbitrarily large messages via SMTP or HTTP, leading to an out-of-memory (OOM) condition and subsequent process termination. The default configuration binds listeners to `[::]:1025` (SMTP) and `[::]:8025` (HTTP) without authentication, exacerbating the risk. The issue affects Mailpit versions prior to 1.30.0.

## Attack Chain

1.  Attacker establishes a connection to the Mailpit SMTP server on `[::]:1025` or the HTTP server on `[::]:8025`.
2.  For SMTP, the attacker sends `HELO`, `MAIL FROM`, and `RCPT TO` commands to initiate a mail transaction.
3.  The attacker sends the `DATA` command, signaling the start of the message body.
4.  The attacker sends an arbitrarily large amount of data as the message body. Since the `MaxSize` limit is not enforced, the server buffers all incoming data in memory.
5.  For HTTP, the attacker sends a `POST` request to `/api/v1/send` with a large JSON payload in the request body, without exceeding the server's read timeout.
6.  Mailpit attempts to process the excessively large message, leading to high memory consumption.
7.  Memory usage continues to increase as the attacker sends more data, exceeding available system resources.
8.  The Mailpit process is terminated by the operating system due to an out-of-memory (OOM) condition, resulting in a denial-of-service.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to perform a denial-of-service attack against Mailpit installations. This can lead to service disruption, preventing legitimate users from utilizing the email testing functionality. Observed memory amplification reaches factors of 7-10x. The attack also fills disk space as oversized messages are persisted to the SQLite store.

## Recommendation

*   Upgrade Mailpit to version 1.30.0 or later to remediate CVE-2026-45713.
*   Deploy the Sigma rule "Detect Mailpit Excessive SMTP Data" to identify potential exploitation attempts by monitoring for unusually large SMTP data transfers.
*   Deploy the Sigma rule "Detect Mailpit Excessive HTTP API Send Payload" to identify potential exploitation attempts by monitoring for unusually large HTTP POST requests to the `/api/v1/send` endpoint.
*   Consider implementing network-level rate limiting on ports 1025 (SMTP) and 8025 (HTTP) to mitigate the impact of potential DoS attacks.
*   Monitor system resource utilization (CPU, memory, disk I/O) on servers running Mailpit to detect anomalous behavior.
