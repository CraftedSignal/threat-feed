---
title: Missing Authorization Vulnerability in CheckCle
slug: 2026-10-checkcle-auth-bypass
description: CheckCle versions up to 1.6.0 contain a critical missing authorization vulnerability allowing unauthenticated access to database records via improperly configured PocketBase API rules.
date: "2026-10-19T16:07:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:checkcle:checkcle:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - cve-2026-112292
vendors:
  - CheckCle
products:
  - CheckCle (<= 1.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CheckCle through 1.6.0 contains a missing authorization vulnerability that allows unauthenticated attackers to read, modify and delete records.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1565.001
    technique_name: 'Data Manipulation: Stored Data Manipulation'
    evidence: Attackers can ... disable alerting, alter status pages, or delete monitoring data.
    confidence_band: high
cves:
  - id: CVE-2026-112292
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112292
rules:
  - title: Detects CVE-2026-112292 Exploitation - Unauthenticated Access to CheckCle Collections
    description: Detects unauthenticated HTTP requests to the CheckCle PocketBase /api/collections/ endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all instances of CheckCle to a version newer than 1.6.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-112292 description
  hunt_leads:
    - lead: Identify unauthorized access to /api/collections/ paths in web server logs
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated CRUD operations via API endpoints
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to CheckCle API endpoints
      owner: IT Operations
      addresses: CVE-2026-112292
      evidence: Missing authorization allows unauthenticated access
---

CheckCle through version 1.6.0 suffers from a missing authorization vulnerability (CVE-2026-112292) stemming from the underlying use of PocketBase with default empty API rules. This misconfiguration exposes the database to unauthenticated remote attackers. An attacker can interact directly with the /api/collections/ endpoint to perform unauthorized CRUD operations on stored data. This vulnerability allows for the extraction of highly sensitive information, including server tokens and alert configurations. Furthermore, successful exploitation enables adversaries to disrupt monitoring operations by disabling alerts, tampering with status pages, or purging historical monitoring data. The simplicity of the exploit path makes this a high-impact risk for organizations relying on CheckCle for infrastructure oversight.

## Attack Chain

1. Attacker performs reconnaissance to identify a CheckCle instance exposed to the internet.
2. Attacker probes the /api/collections/ endpoint to determine if PocketBase is accessible without authentication.
3. Attacker identifies available collections by querying the API catalog.
4. Attacker crafts HTTP GET or POST requests to retrieve or modify records within identified collections.
5. Attacker exfiltrates sensitive data, such as `server_token` values and `alert_configurations` secrets, via API responses.
6. Attacker modifies or deletes records to disable security alerting or manipulate incident status pages.
7. Attacker successfully disrupts system monitoring and achieves unauthorized persistence through configuration tampering.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.8. Exploitation leads to full unauthorized access to monitored infrastructure data. This can result in complete loss of confidentiality regarding server tokens and alert mechanisms, as well as loss of integrity and availability of monitoring status and alerting systems. Any organization using CheckCle version 1.6.0 or earlier is potentially exposed to data theft and the weaponization of the monitoring platform itself.

## Recommendation

1. Upgrade CheckCle to the latest available version beyond 1.6.0 immediately to resolve the improper PocketBase configuration.
2. Implement strict network access controls (e.g., VPN or IP allowlisting) to restrict access to the /api/collections/ endpoint to authorized internal segments only.
3. Deploy the webserver-based Sigma rule provided in this brief to detect unauthorized API access patterns targeting the /api/collections/ endpoint.
4. Conduct an audit of existing CheckCle data for signs of unauthorized access or modification, focusing on records within `alert_configurations` and `status_pages`.
