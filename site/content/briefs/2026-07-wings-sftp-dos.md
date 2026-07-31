---
title: Pterodactyl Wings SFTP Service Denial of Service
slug: 2026-07-wings-sftp-dos
description: An unauthenticated remote attacker can trigger a panic and crash the Pterodactyl Wings service by sending a maliciously crafted packet during the SFTP handshake.
date: "2026-07-31T19:30:26Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - pterodactyl
  - go
  - vulnerability
vendors:
  - Pterodactyl
products:
  - wings
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A maliciously crafted packet received & parsed during the SFTP connection handshake will cause a Go panic.
    confidence_band: high
cves:
  - id: CVE-2026-52856
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-ghrq-5wpp-hxx5
  - https://github.com/pterodactyl/wings/releases/tag/v1.13.0
---

Pterodactyl Wings, a service used for managing game server instances, is vulnerable to a denial-of-service (DoS) condition in its integrated SFTP server implementation. The vulnerability, identified as CVE-2026-52856, stems from improper input validation during the initial SFTP connection handshake. A remote, unauthenticated attacker can send a specifically crafted network packet that causes an uncaught exception (Go panic) within the application's runtime. This leads to the immediate termination of the Wings process, rendering the management agent unavailable. This vulnerability affects all versions of Pterodactyl Wings prior to 1.13.0. Defenders should note that because the crash occurs during the early handshake phase, the attack does not require valid credentials or an established session, making it highly accessible to remote actors.

## Attack Chain

1. Attacker performs network reconnaissance to identify target servers exposing the Pterodactyl Wings SFTP port (default TCP 2022).
2. Attacker initiates an unauthenticated TCP connection to the identified SFTP port.
3. The service begins the SFTP handshake process, expecting valid protocol headers.
4. Attacker transmits a maliciously crafted, malformed packet designed to bypass input validation filters.
5. The application parses the malformed packet using vulnerable index-handling logic.
6. The parsing logic triggers an uncaught exception or assertion failure within the Go runtime.
7. The Go runtime triggers a panic, causing the Wings process to crash immediately.
8. Final Objective: Successful denial of service against the Pterodactyl management infrastructure.

## Impact

The vulnerability results in the total loss of availability for the Pterodactyl Wings service. For environments hosting game servers, this results in the inability to manage, start, stop, or configure server instances. If an attacker systematically targets a fleet of Wings nodes, they can cause widespread administrative outages across an entire hosting environment.

## Recommendation

Prioritized actions for detection and remediation teams:
- Upgrade all instances of Pterodactyl Wings to version 1.13.0 or later immediately to patch CVE-2026-52856.
- If immediate patching is not possible, restrict access to the SFTP service port via firewall rules to known-only administrative IP addresses.
- Monitor webserver/proxy logs or firewall connection logs for high-frequency or anomalous connection attempts directed at the SFTP port, which may indicate scanning or exploitation activity.
- Ensure that process monitoring is configured to automatically restart the Wings service if it enters a non-running state.
