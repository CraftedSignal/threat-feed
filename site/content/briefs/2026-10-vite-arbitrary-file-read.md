---
brief_id: brief-2026-10-24-vite-arbitrary-file-read
event_id: brief-2026-10-24-vite-arbitrary-file-read
revision: 1
activity_at: "2026-10-24T21:31:08Z"
title: 'Vitejs and Voidzero Vite: Arbitrary File Read (CVE-2026-39636)'
slug: 2026-10-vite-arbitrary-file-read
description: Vitejs and Voidzero Vite contain a vulnerability (CVE-2026-39636) in the WebSocket-based fetchModule call that allows unauthenticated attackers to bypass filesystem checks and read arbitrary files by injecting file:// URLs into WebSocket payloads.
date: "2026-10-24T21:31:08Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
tags:
  - arbitrary-file-read
  - web-vulnerability
  - websocket
  - vite
vendors:
  - Vitejs
  - Voidzero
products:
  - Vite (<= 6.4.1, 7.3.1, 8.0.4)
  - Vite (<= 0.1.15)
cves:
  - id: CVE-2026-39636
    cvss: 6.5
    epss: 0.00224
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CATCHCATOOO-CVE-2026-39636-VULNERABILITY-EXP
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CATCHCATOOO-CVE-2026-39636-VULNERABILITY-EXP&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Vite environments to versions > 8.0.4 (Vitejs) or > 0.1.15 (Voidzero)
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects Vitejs Vite <= 8.0.4 and Voidzero Vite <= 0.1.15
  hunt_leads:
    - lead: Identify unauthorized WebSocket connections or abnormal fetchModule activity on internal development servers
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Proxy logs for WebSocket (WSS) traffic
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves exploitation of WebSocket-based fetchModule call via file:// URL injection
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Vite WebSocket interfaces (default port 8080) to trusted IP segments
      owner: IT Operations
      addresses: CVE-2026-39636
      evidence: Exploit targets exposed WebSocket interfaces on port 8080
---

CVE-2026-39636 is a high-severity vulnerability affecting Vitejs Vite and Voidzero Vite that permits unauthorized reading of arbitrary files from the host system. The vulnerability originates from insufficient validation within the WebSocket-based fetchModule component. Attackers can bypass existing HTTP filesystem security controls by sending a file:// URL within a WebSocket payload. A public proof-of-concept exploit script has been published, targeting WebSocket interfaces often exposed on port 8080.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files from the filesystem of the server running the affected Vite application, potentially leading to the disclosure of sensitive source code, configuration files, or environment variables.

## Recommendation

- Upgrade Vitejs Vite installations to versions beyond 8.0.4.
- Upgrade Voidzero Vite installations to versions beyond 0.1.15.
- Audit infrastructure for Vite development or build servers exposing WebSocket interfaces to untrusted networks, particularly on port 8080.
- Implement network-level access controls to restrict access to the Vite development server interface to authorized internal IP ranges only.
