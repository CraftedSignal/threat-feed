---
title: Multiple Authentication and Session Vulnerabilities in Monta monta.app
slug: 2026-10-monta-app-vulns
description: Multiple vulnerabilities in the Monta monta.app platform allow unauthenticated remote attackers to hijack sessions, impersonate charging stations, and disrupt services via insecure WebSocket communication.
date: "2026-10-01T17:06:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - ics
  - web-application
  - energy
  - transportation
vendors:
  - Monta
products:
  - monta.app (all versions)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: WebSocket endpoints lack proper authentication mechanisms, enabling attackers to impersonate charging stations.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This absence of rate limiting may allow an attacker to conduct denial-of-service attacks or brute-force attacks to gain unauthorized access.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-02
  - https://www.cve.org/CVERecord?id=CVE-2026-95102
  - https://www.cve.org/CVERecord?id=CVE-2026-97363
  - https://www.cve.org/CVERecord?id=CVE-2026-97212
  - https://www.cve.org/CVERecord?id=CVE-2026-93474
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Enable OCPP 1.6 Security Profile 2 for all connected charging infrastructure
      owner: IT Operations
      due: 72h
      evidence: Mitigation stated in CVE-2026-95102, CVE-2026-97363, CVE-2026-97212
  mitigation_plan:
    - priority: immediate
      action: Implement rate limiting and connection throttling at the WebSocket gateway level
      owner: IT Operations
      addresses: CVE-2026-97363
      evidence: Remediation provided by Monta
---

The Monta monta.app platform is affected by a series of critical vulnerabilities (CVE-2026-95102, CVE-2026-97363, CVE-2026-97212, CVE-2026-93474) related to insecure WebSocket management. These flaws stem from missing authentication for critical functions, inadequate rate limiting, and predictable session identifiers. Attackers can leverage the public availability of station identifiers to target the WebSocket backend, allowing them to impersonate valid charging stations or perform brute-force attacks against the authentication API. Because the backend does not sufficiently validate session integrity, an attacker can hijack existing station connections or trigger denial-of-service (DoS) conditions. These vulnerabilities impact the reliability of charging infrastructure globally, posing risks to both service availability and the security of sensitive operational data.

## Impact

Successful exploitation can lead to unauthorized administrative control over charging stations, enabling attackers to modify charging parameters, exfiltrate station data, or disable charging services entirely. These vulnerabilities impact the Energy and Transportation sectors worldwide. If successfully exploited, an attacker could disrupt critical charging networks, resulting in denial-of-service or physical asset manipulation by authorized command spoofing.

## Recommendation

- Enable OCPP 1.6 Security Profile 2 (HTTP Basic Authentication with TLS) for all managed charging stations to remediate the lack of authentication mechanisms (CVE-2026-95102).
- Configure robust rate limiting and connection throttling at the network edge to mitigate brute-force and DoS attempts against the WebSocket API (CVE-2026-97363).
- Monitor for anomalous WebSocket traffic patterns, specifically rapid reconnection attempts or excessive command volume directed at the charging station backend, which may indicate exploitation of CVE-2026-97212.
- Review public-facing web platforms and registries to limit the exposure of charging station authentication identifiers that facilitate targeted exploitation (CVE-2026-93474).
