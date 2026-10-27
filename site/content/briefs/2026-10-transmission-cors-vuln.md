---
brief_id: brief-2026-10-27-transmission-cors-vuln
event_id: brief-2026-10-27-transmission-cors-vuln
revision: 1
activity_at: "2026-10-27T07:48:38Z"
title: 'Transmission: Permissive CORS vulnerability (CVE-2026-116748)'
slug: 2026-10-transmission-cors-vuln
description: Transmission versions prior to 4.1.3 contain a permissive CORS vulnerability in the RPC server that allows unauthorized origins to capture the X-Transmission-Session-Id token and execute arbitrary RPC commands.
date: "2026-10-27T07:48:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:transmissionbt:transmission:*:*:*:*:*:*:*:*
vendors:
  - Transmission
products:
  - Transmission (< 4.1.3)
cves:
  - id: CVE-2026-116748
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116748
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Identify unauthorized access to the Transmission RPC interface from unusual web origins
      technique_id: T1505.003
      data_needed:
        - Web server access logs or proxy logs for the Transmission RPC interface
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Malicious web pages can read the token from the 409 handshake response and replay it to issue RPC calls
  mitigation_plan:
    - priority: immediate
      action: Upgrade Transmission to version 4.1.3 or later
      owner: IT Operations
      addresses: CVE-2026-116748
      evidence: Transmission 4.0.0 before 4.1.3 contains a permissive CORS vulnerability
---

Transmission versions 4.0.0 through 4.1.2 contain a permissive Cross-Origin Resource Sharing (CORS) vulnerability within the `handle_request()` function in `rpc-server.cc`. This vulnerability allows any web origin to read the `X-Transmission-Session-Id` anti-CSRF token during a 409 handshake response. By obtaining this token, an unauthorized actor can perform authenticated RPC requests, resulting in unauthorized configuration changes or data deletion.

## Impact

Successful exploitation allows an unauthorized remote actor to perform several administrative actions, including:
- Modifying the download directory.
- Deleting torrents and local data.
- Executing scripts via the `script-torrent-done` feature, which may lead to arbitrary command execution on the host running the Transmission RPC server.

## Recommendation

- Upgrade Transmission to version 4.1.3 or later immediately to resolve the insecure CORS handling.
- Restrict access to the Transmission RPC interface to trusted networks only using firewall rules or a reverse proxy.
- Review `script-torrent-done` configurations to ensure that no malicious scripts are configured to trigger upon torrent completion.
