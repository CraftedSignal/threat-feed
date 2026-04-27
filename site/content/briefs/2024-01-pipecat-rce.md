---
title: Pipecat Remote Code Execution via Pickle Deserialization in LivekitFrameSerializer
slug: 2024-01-pipecat-rce
description: A critical vulnerability, CVE-2025-62373, exists in Pipecat's LivekitFrameSerializer where the deserialize() method uses Python's pickle.loads() on WebSocket data without validation, allowing a malicious WebSocket client to execute arbitrary code on the Pipecat server if LivekitFrameSerializer is explicitly enabled.
date: "2024-01-02T10:00:00Z"
severities:
  - critical
tags:
  - remote code execution
  - deserialization
  - pipecat
vendors:
  - pip
products:
  - pipecat-ai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1205
    technique_name: Traffic Signaling
cves:
  - id: CVE-2025-62373
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-c2jg-5cp7-6wc7
ioc_counts:
  ip: 1
rules:
  - title: Detect Pipecat WebSocket Connections from Non-Localhost
    description: Detects WebSocket connections to Pipecat servers that are not bound to localhost, which is a prerequisite for exploiting CVE-2025-62373 when LivekitFrameSerializer is used.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - linux
  - title: Detect Pipecat Suspicious Process Execution
    description: Detects unusual processes being spawned from the Pipecat server, indicative of potential RCE exploitation (e.g., via pickle deserialization).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability (CVE-2025-62373) exists in Pipecat's `LivekitFrameSerializer`, an optional, non-default, and now deprecated frame serializer class intended for LiveKit integration. The `deserialize()` method in `src/pipecat/serializers/livekit.py` uses Python's `pickle.loads()` on data received from WebSocket clients without validation or sanitization. This allows a malicious WebSocket client to send a crafted pickle payload to execute arbitrary code on the Pipecat server. While…
