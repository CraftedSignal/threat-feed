---
brief_id: brief-2026-10-26-openhands-rce
event_id: brief-2026-10-26-openhands-rce
revision: 1
activity_at: "2026-10-26T17:44:18Z"
title: 'OpenHands Agent SDK: Unauthenticated remote code execution (CVE-2026-112346)'
slug: 2026-10-openhands-rce
description: OpenHands Software Agent SDK before 1.52.0 contains an unauthenticated remote code execution vulnerability due to insecure workspace launcher network binding and disabled authentication.
date: "2026-10-26T17:44:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:openhands:agent_sdk:*:*:*:*:*:*:*:*
vendors:
  - OpenHands
products:
  - Agent SDK (< 1.52.0)
cves:
  - id: CVE-2026-112346
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112346
---

OpenHands Software Agent SDK before 1.52.0 contains an unauthenticated remote code execution vulnerability where the DockerWorkspace and Apptainer workspace launchers bind the sandbox agent server to all network interfaces (0.0.0.0) with an empty session_api_keys list, disabling authentication by default. Attackers who can reach the published container port can send unauthenticated HTTP and WebSocket requests to execute arbitrary shell commands as root in the sandbox, access the mounted workspace, and read plaintext secrets from the secrets store.
