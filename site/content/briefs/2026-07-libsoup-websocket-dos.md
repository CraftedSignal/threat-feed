---
title: libsoup Websocket Unbounded Decompression Denial of Service Vulnerability
slug: 2026-07-libsoup-websocket-dos
description: A remote denial of service vulnerability, CVE-2026-15709, exists in the libsoup library's websocket permessage-deflate extension, allowing an attacker to trigger a denial of service through unbounded decompression.
date: "2026-07-17T07:09:20Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - libsoup
vendors:
  - The libsoup project
products:
  - libsoup
cves:
  - id: CVE-2026-15709
    cvss: 7.5
    epss: 0.00548
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15709
---

A significant remote denial of service vulnerability, identified as CVE-2026-15709, has been disclosed within the `libsoup` library. This vulnerability specifically impacts the `libsoup` implementation of the websocket `permessage-deflate` extension, which is designed to compress websocket messages. The flaw lies in an unbounded decompression mechanism, meaning that when a specially crafted, highly compressed message is received, the `libsoup` library attempts to decompress it without adequate resource limits. This uncontrolled decompression leads to excessive consumption of memory and CPU resources on the server. If successfully exploited, this can render the affected application or even the entire system unresponsive, causing a denial of service and disrupting critical operations. Given `libsoup`'s role as a fundamental HTTP client/server library, numerous applications could be at risk.

## Attack Chain

1. An attacker identifies a publicly accessible application utilizing the vulnerable `libsoup` library for websocket communication.
2. The attacker establishes a websocket connection with the target application.
3. During the websocket handshake, the attacker negotiates the use of the `permessage-deflate` extension.
4. The attacker sends specially crafted, highly compressed websocket messages through the established connection.
5. The vulnerable `libsoup` library on the server attempts to decompress these messages.
6. Due to the unbounded decompression vulnerability (CVE-2026-15709), the decompression process consumes an inordinate amount of server memory and CPU.
7. The target application's resources are exhausted, causing it to become unresponsive or crash, leading to a denial of service for legitimate users.

## Impact

A successful exploitation of CVE-2026-15709 would result in the denial of service for applications or systems relying on the vulnerable `libsoup` library. This can lead to severe operational disruptions, causing downtime for services, loss of productivity, and potential financial impact for organizations. While no specific victim counts or sectors are currently disclosed, any service utilizing the affected `libsoup` version that handles websocket connections with `permessage-deflate` is potentially vulnerable to resource exhaustion and service unavailability.

## Recommendation

* Patch CVE-2026-15709 on all systems using the `libsoup` library immediately to mitigate the remote denial of service vulnerability.
