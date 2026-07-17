---
title: Libsoup WebSocket Remote Denial of Service Vulnerability
slug: 2026-07-libsoup-dos
description: A remote denial of service vulnerability, CVE-2026-15711, exists in the libsoup library's WebSocket connection handling due to an oversized control frame protocol violation, allowing an attacker to cause service disruption.
date: "2026-07-17T07:08:38Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - libsoup
  - websocket
vendors:
  - Libsoup
products:
  - libsoup
cves:
  - id: CVE-2026-15711
    cvss: 7.5
    epss: 0.00431
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15711
---

A remote denial of service (DoS) vulnerability, identified as CVE-2026-15711, has been disclosed in the libsoup library. Libsoup is an HTTP client/server library for GNOME. This vulnerability specifically impacts the library's `soupwebsocketconnection` component, which handles WebSocket communication. The flaw arises from an improper handling of oversized control frames, which constitutes a protocol violation within the WebSocket specification. An attacker can exploit this by sending a malformed or excessively large control frame to a system using the vulnerable libsoup component, leading to resource exhaustion or application instability, ultimately resulting in a denial of service. The Microsoft Security Response Center (MSRC) published an advisory on July 17, 2026, confirming the vulnerability. The specific conditions under which this vulnerability manifests and any observed exploitation attempts in the wild are not detailed in the available information.

## Attack Chain

This brief describes a vulnerability and its exploitation mechanism rather than a full attack campaign. The following steps outline how an attacker could leverage CVE-2026-15711:

1. **Target Identification**: An attacker identifies a server or application utilizing the vulnerable `libsoup` library for WebSocket communication.
2. **Connection Establishment**: The attacker initiates a WebSocket connection to the targeted server.
3. **Crafting Malicious Frame**: The attacker crafts a WebSocket control frame (e.g., a PING, PONG, CLOSE frame) that exceeds the expected or allowed size limits, violating the WebSocket protocol specification (RFC 6455).
4. **Transmission**: The oversized control frame is sent over the established WebSocket connection to the `soupwebsocketconnection` component of the `libsoup` library.
5. **Protocol Violation Trigger**: The `libsoup` component processes the oversized control frame, encountering a protocol violation due to its excessive size.
6. **Resource Exhaustion/Crash**: This improper handling leads to unrecoverable errors, memory issues, or a crash within the application or service utilizing `libsoup`.
7. **Denial of Service**: The targeted application or service becomes unresponsive or terminates, resulting in a denial of service for legitimate users.

## Impact

Successful exploitation of CVE-2026-15711 leads directly to a denial of service condition for applications or services relying on the vulnerable `libsoup` library for WebSocket functionality. While the provided information does not specify the scope of targeting or the number of victims, any system that incorporates an unpatched version of `libsoup` and exposes WebSocket endpoints is potentially vulnerable. The impact can range from temporary service disruptions and loss of availability to data processing interruptions, affecting critical business operations depending on the targeted service's role.

## Recommendation

* Apply the latest security updates provided by the vendor or upstream project for `libsoup` to patch CVE-2026-15711 immediately.
* Monitor systems for unusual service crashes or restarts that could indicate a denial of service event, especially on applications exposed to external WebSocket connections.
