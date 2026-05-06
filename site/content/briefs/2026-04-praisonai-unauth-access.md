---
title: PraisonAI Unauthenticated Agent Activity Exposure (CVE-2026-39889)
slug: 2026-04-praisonai-unauth-access
description: PraisonAI versions prior to 4.5.115 expose agent activity without authentication due to improperly secured A2U event stream endpoints, potentially allowing unauthorized access to sensitive agent information.
date: "2026-04-08T21:17:01Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-39889
  - information-disclosure
  - web-application
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-39889
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39889
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-f292-66h9-fpmf
rules:
  - title: Detect Unauthenticated Access to PraisonAI A2U Endpoints
    description: Detects unauthenticated HTTP GET requests to PraisonAI A2U endpoints, indicating potential exploitation of CVE-2026-39889.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Detect Access to PraisonAI A2U Endpoints - Wildcard
    description: Detects unauthenticated HTTP GET requests to PraisonAI A2U endpoints, indicating potential exploitation of CVE-2026-39889, using a wildcard for event streams.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is vulnerable to unauthenticated information disclosure in versions prior to 4.5.115. The vulnerability, identified as CVE-2026-39889, stems from the A2U (Agent-to-User) event stream server exposing sensitive agent activity without proper authentication. The `create_a2u_routes()` function registers several endpoints, including `/a2u/info`, `/a2u/subscribe`, `/a2u/events/{stream_name}`, `/a2u/events/sub/{id}`, and `/a2u/health`, without implementing authentication checks. An attacker can exploit this flaw to gain unauthorized insight into agent operations within the PraisonAI system. This vulnerability was reported on April 8, 2026, and patched in version 4.5.115.

## Attack Chain

1.  The attacker identifies a PraisonAI instance running a version prior to 4.5.115.
2.  The attacker sends an HTTP GET request to the `/a2u/info` endpoint.
3.  The server responds with information about the available agent activity streams without requiring any authentication.
4.  The attacker subscribes to a specific agent activity stream by sending an HTTP GET request to `/a2u/subscribe`.
5.  The server provides the attacker with a stream ID, again without authentication.
6.  The attacker then requests event data from the `/a2u/events/{stream_name}` endpoint, substituting `{stream_name}` with a valid stream name obtained from `/a2u/info`.
7.  Alternatively, the attacker requests event data from the `/a2u/events/sub/{id}` endpoint, where '{id}' is a stream ID obtained from `/a2u/subscribe`.
8.  The server streams agent activity data to the attacker, enabling them to monitor agent actions and potentially extract sensitive information. The final objective is to gain unauthorized access to agent activity data.

## Impact

Successful exploitation of CVE-2026-39889 can lead to the unauthorized disclosure of sensitive information related to agent activity within the PraisonAI system. This could include confidential data processed by the agents, internal operational details, and potentially credentials or API keys used by the agents. While the exact number of affected installations is unknown, any organization using PraisonAI versions prior to 4.5.115 is potentially vulnerable.

## Recommendation

*   Upgrade PraisonAI installations to version 4.5.115 or later to remediate CVE-2026-39889.
*   Monitor web server logs for requests to the `/a2u/info`, `/a2u/subscribe`, `/a2u/events/{stream_name}`, `/a2u/events/sub/{id}`, and `/a2u/health` endpoints without prior authentication. Consider deploying the Sigma rule provided below to detect such activity.
*   Implement network access controls to restrict access to the PraisonAI server to only authorized users and systems.
