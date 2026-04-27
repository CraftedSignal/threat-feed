---
title: PraisonAI SSRF Vulnerability via Unvalidated Webhook URL
slug: 2024-01-praisonai-ssrf
description: PraisonAI versions prior to 4.5.128 are vulnerable to Server-Side Request Forgery (SSRF) due to a lack of URL validation on the webhook_url parameter in the /api/v1/runs endpoint, allowing unauthenticated attackers to send arbitrary POST requests from the server.
date: "2026-04-09T22:16:35Z"
severities:
  - high
tags:
  - ssrf
  - praisonai
  - cve-2026-40114
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
cves:
  - id: CVE-2026-40114
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40114
rules:
  - title: Detect Suspicious Webhook URL in PraisonAI Runs Endpoint
    description: Detects suspicious webhook URLs in requests to the /api/v1/runs endpoint of PraisonAI, indicating potential SSRF exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from PraisonAI Server to Private IP Ranges
    description: Detects network connections from the PraisonAI server to private IP address ranges, which may indicate SSRF attacks targeting internal resources.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to a Server-Side Request Forgery (SSRF) vulnerability affecting versions prior to 4.5.128. The vulnerability resides in the `/api/v1/runs` endpoint, which accepts a `webhook_url` parameter in the request body without proper validation. This allows an unauthenticated attacker to specify an arbitrary URL, causing the PraisonAI server to send an HTTP POST request to that URL upon job completion. This flaw enables attackers to target internal…
