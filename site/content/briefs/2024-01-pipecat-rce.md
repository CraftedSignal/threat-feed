---
title: Pipecat Remote Code Execution via Pickle Deserialization in LivekitFrameSerializer
slug: 2024-01-pipecat-rce
description: A critical vulnerability, CVE-2025-62373, exists in Pipecat's LivekitFrameSerializer where the deserialize() method uses Python's pickle.loads() on WebSocket data without validation, allowing a malicious WebSocket client to execute arbitrary code on the Pipecat server if LivekitFrameSerializer is explicitly enabled.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: ip
    value: 0.0.0.0
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

A critical vulnerability (CVE-2025-62373) exists in Pipecat's `LivekitFrameSerializer`, an optional, non-default, and now deprecated frame serializer class intended for LiveKit integration. The `deserialize()` method in `src/pipecat/serializers/livekit.py` uses Python's `pickle.loads()` on data received from WebSocket clients without validation or sanitization. This allows a malicious WebSocket client to send a crafted pickle payload to execute arbitrary code on the Pipecat server. While `LivekitFrameSerializer` is not enabled by default and was deprecated in version 0.0.90 in favor of the safer `LiveKitTransport` method, it remains in the codebase and could be inadvertently used, posing a severe risk if a Pipecat server is configured to use it and is listening on an external interface.

## Attack Chain

1.  Attacker identifies a Pipecat server with an exposed WebSocket endpoint (e.g., listening on 0.0.0.0:8765) using the vulnerable `LivekitFrameSerializer`.
2.  Attacker crafts a malicious Python pickle payload. This payload contains instructions to execute arbitrary code on the server, using techniques like defining a class with a `__reduce__` method that calls `os.system()`.
3.  Attacker establishes a WebSocket connection to the Pipecat server.
4.  Attacker sends the crafted pickle payload as a WebSocket message to the server.
5.  The Pipecat server receives the message and passes the data to the `LivekitFrameSerializer.deserialize()` method.
6.  The `deserialize()` method calls `pickle.loads()` on the attacker-controlled data without proper validation.
7.  `pickle.loads()` deserializes the malicious pickle object, triggering the execution of the attacker's code on the server with the privileges of the Pipecat process.
8.  Attacker achieves remote code execution, potentially leading to full compromise of the server, including data exfiltration, malware installation, or pivoting to other systems.

## Impact

Successful exploitation of this vulnerability, CVE-2025-62373, allows an attacker to achieve remote code execution on the Pipecat server. If an application uses `LivekitFrameSerializer` and exposes the Pipecat WebSocket server to untrusted networks, an attacker can completely compromise the server. This could lead to the execution of operating system commands, data modification, malware installation, or pivoting to other systems. The vulnerability is critical because any code execution flaw in a real-time communications server context poses a high risk.

## Recommendation

*   Immediately stop using the `LivekitFrameSerializer` due to its use of unsafe pickle deserialization. Migrate to the recommended `LiveKitTransport` or other secure methods provided by the Pipecat framework (see Overview).
*   Update Pipecat to a version >= 0.0.94 to receive the deprecation warning.
*   If you must support LiveKit integration or binary frame serialization, use safer alternatives like JSON, Protocol Buffers, or MessagePack.
*   Bind the Pipecat service to localhost (127.0.0.1) whenever possible to prevent external network access as mentioned in the Overview.
*   Implement authentication and authorization on the WebSocket connection to restrict who can send data to the server, as described in the Mitigation section.
