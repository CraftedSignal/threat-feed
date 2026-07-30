---
title: MeshCentral WebSocket Hijacking Vulnerability
slug: 2026-07-meshcentral-websocket-hijacking
description: CVE-2026-66420 is a high-severity vulnerability in MeshCentral 1.1.21 allowing unauthenticated attackers to hijack administrator sessions via a cross-site WebSocket hijacking protection bypass.
date: "2026-07-30T23:32:35Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - MeshCentral
products:
  - MeshCentral (1.1.21)
cves:
  - id: CVE-2026-66420
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66420
---

MeshCentral version 1.1.21 is vulnerable to a cross-site WebSocket hijacking protection bypass (CVE-2026-66420). The vulnerability is rooted in an unconditional early return within the CheckWebServerOriginName() function located in webserver.js, which is triggered when the instance is configured to use self-signed certificates. Because of this logic error, the application fails to validate the origin of incoming WebSocket connections.

An unauthenticated remote attacker can leverage this flaw by initiating cross-origin WebSocket requests to any of the twelve available MeshCentral WebSocket endpoints. By sending crafted action commands, an attacker can exfiltrate the server sessionKey. Possession of this key allows the attacker to forge session tokens for arbitrary users, including administrators, effectively granting full remote control over the MeshCentral server and all managed endpoints. This vulnerability is particularly critical for deployments relying on default or self-signed certificate configurations.

## Impact

Successful exploitation leads to a complete compromise of the MeshCentral management server. Attackers gain the ability to forge administrator sessions, bypass authentication, and exercise full remote control over every device managed by the affected instance. This represents a significant risk for organizations managing large fleets of remote assets, as it permits lateral movement, data exfiltration, and persistent access to the managed infrastructure.

## Recommendation

- Upgrade all MeshCentral instances to a version where this vulnerability is remediated.
- If immediate patching is not feasible, transition from self-signed certificates to certificates signed by a trusted Certificate Authority (CA) to prevent the trigger of the flawed code path.
- Review access logs for unusual cross-origin requests targeting WebSocket endpoints, particularly those originating from external domains.
- Conduct a full audit of all managed devices and active sessions if the MeshCentral instance is suspected of having been compromised.
