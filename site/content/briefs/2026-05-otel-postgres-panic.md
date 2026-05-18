---
title: OpenTelemetry eBPF Instrumentation Postgres Parser Vulnerable to Panic via Malformed BIND Payloads (CVE-2026-45678)
slug: 2026-05-otel-postgres-panic
description: The OpenTelemetry eBPF Instrumentation (OBI) Postgres protocol parser is vulnerable to a remote availability issue — when processing BIND messages, the parser assumes payloads contain a valid NUL-terminated portal name; a crafted empty or unterminated payload can cause OBI to slice beyond the end of the captured buffer, triggering a runtime panic and crashing the agent.
date: "2026-05-18T17:58:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - postgres
  - ebpf
  - CVE-2026-45678
vendors:
  - opentelemetry
products:
  - go/go.opentelemetry.io/obi (< 0.9.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-pgvv-q3wf-mm9m
  - https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/d5691806adc98008bacd2b7a4a4e0cd38ea51227/pkg/components/ebpf/common/sql_detect_postgres.go#L286-L294
rules:
  - title: Detect OBI Postgres Parser Panic Attempt
    description: Detects CVE-2026-45678 exploitation — attempts to trigger a panic in the OpenTelemetry eBPF Instrumentation Postgres parser by sending malformed BIND messages
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
  - title: Detect OBI Process Crash
    description: Detects an OBI process crashing, which may indicate exploitation of CVE-2026-45678
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The OpenTelemetry eBPF Instrumentation (OBI) is vulnerable to a denial-of-service attack due to improper handling of malformed Postgres BIND messages. The vulnerability, identified as CVE-2026-45678, resides in the Postgres protocol parser within OBI's eBPF component. Specifically, the parser incorrectly assumes that BIND message payloads contain a valid NUL-terminated portal name. By sending a crafted BIND message with either an empty payload or a payload lacking the NUL terminator, an attacker can cause the parser to read beyond the bounds of the buffer, triggering a runtime panic. This panic results in the OBI agent crashing, disrupting telemetry collection for the affected node or process. The issue affects OBI versions prior to 0.9.0.

## Attack Chain

1. An attacker identifies a target system running OBI monitoring a Postgres database.
2. The attacker crafts a malformed Postgres BIND message. This message either contains an empty payload or lacks the expected NUL terminator after the portal name.
3. The attacker sends the crafted BIND message to the Postgres database server being monitored.
4. OBI intercepts the network traffic using eBPF and captures the malformed BIND message.
5. The OBI Postgres protocol parser attempts to process the BIND message payload in `pkg/ebpf/common/sql_detect_postgres.go`.
6. Due to the missing NUL terminator or empty payload, the `portalLen` calculation results in a value exceeding the buffer's boundaries.
7. The subsequent slice operation `msg.data[portalLen:]` triggers a "slice bounds out of range" runtime panic.
8. The OBI agent crashes, halting telemetry collection from the monitored system.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, specifically impacting the availability of telemetry data. An attacker can repeatedly send malformed Postgres BIND messages to crash the OBI agent, effectively blinding monitoring systems and preventing the detection of other potential security incidents. This vulnerability primarily affects organizations using OBI for monitoring Postgres databases. The impact is a loss of visibility into database performance and security, potentially leading to delayed incident response and increased risk.

## Recommendation

*   Upgrade to OpenTelemetry eBPF Instrumentation version 0.9.0 or later to patch CVE-2026-45678.
*   Deploy the Sigma rule "Detect OBI Postgres Parser Panic Attempt" to identify attempts to exploit CVE-2026-45678 by detecting malformed Postgres BIND messages.
*   Monitor network traffic for unexpected patterns of malformed Postgres BIND messages indicative of exploitation attempts, and correlate with OBI agent crashes.
