---
title: Authenticated Identity Spoofing Vulnerability in Velociraptor
slug: 2026-08-velociraptor-auth-bypass
description: Rapid7 Velociraptor versions prior to 0.77.2 are affected by an authenticated identity-spoofing vulnerability, CVE-2026-18972, that may allow unauthorized access or impersonation within the platform.
date: "2026-08-11T18:42:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - identity-management
vendors:
  - Rapid7
products:
  - Velociraptor
cves:
  - id: CVE-2026-18972
    cvss: 9.6
references:
  - https://cyber.gc.ca/en/alerts-advisories/rapid7-security-advisory-av26-801
  - https://docs.velociraptor.app/announcements/advisories/cve-2026-18972/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Velociraptor to version 0.77.2 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory requires update for CVE-2026-18972 mitigation
---

Rapid7 has disclosed a security vulnerability in Velociraptor, an endpoint visibility and incident response platform. The vulnerability, tracked as CVE-2026-18972, is classified as an authenticated identity-spoofing flaw. It affects all versions of Velociraptor prior to 0.77.2. The vulnerability allows an authenticated user to perform identity-spoofing, which may lead to unauthorized actions or elevated privileges within the platform's management console or communication protocol between agents and the server. Because Velociraptor is frequently used for high-privileged forensic tasks, the potential impact of an authenticated attacker successfully masquerading as a different user or administrator is significant for internal security operations. Organizations utilizing Velociraptor should prioritize upgrading to version 0.77.2 or later.

## Impact

Successful exploitation could allow an authenticated attacker to perform unauthorized operations, potentially impacting the integrity of incident response data or allowing for the manipulation of endpoint collection tasks. The number of affected deployments is estimated to be significant among organizations using Velociraptor for forensic monitoring and live response, posing a risk to the security of the internal management network if the Velociraptor server itself is compromised.

## Recommendation

* Upgrade all Velociraptor server and agent deployments to version 0.77.2 or later immediately.
* Audit access logs for the Velociraptor management console and API endpoints for signs of unexpected account impersonation or anomalous login patterns.
* Review all custom forensic VQL queries and tasks initiated within the environment around the time of the update to ensure no unauthorized configurations were injected.
