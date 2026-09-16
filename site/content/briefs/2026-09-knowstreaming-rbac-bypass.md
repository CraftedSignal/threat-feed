---
title: KnowStreaming RBAC Bypass Vulnerability
slug: 2026-09-knowstreaming-rbac-bypass
description: KnowStreaming versions 3.4.1 and earlier contain an improper access control vulnerability in REST API endpoints that allows authenticated users to perform unauthorized privilege escalation.
date: "2026-09-16T21:56:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:knowstreaming:knowstreaming:*:*:*:*:*:*:*:*
vendors:
  - KnowStreaming
products:
  - KnowStreaming (<= 3.4.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can call identity-management endpoints to create administrator accounts or grant themselves administrative privileges without proper authorization.
    confidence_band: high
cves:
  - id: CVE-2026-92780
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92780
rules:
  - title: Detect CVE-2026-92780 Exploitation - Unauthorized Account Creation
    description: Detects unauthorized attempts to access identity management API endpoints potentially related to CVE-2026-92780 exploitation
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch KnowStreaming to a version beyond 3.4.1
      owner: IT Operations
      due: 24h
      evidence: Source states versions through 3.4.1 are affected by CVE-2026-92780
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to KnowStreaming API endpoints
      owner: IT Operations
      addresses: CVE-2026-92780
      evidence: RBAC bypass vulnerability in REST API
---

KnowStreaming versions through 3.4.1 contain a critical improper access control vulnerability, tracked as CVE-2026-92780. The software fails to enforce role-based access control (RBAC) on its REST API endpoints. This flaw allows any authenticated user to interact with sensitive administrative functionality that should be restricted to privileged accounts. Specifically, attackers can target identity-management endpoints to create new administrator accounts or modify existing user permissions to grant themselves administrative privileges. This vulnerability poses a significant risk to the integrity and confidentiality of the KnowStreaming environment, as it effectively nullifies the application's authorization model. Defenders should prioritize patching, as this vulnerability allows a standard user to gain full administrative control over the application.

## Impact

Successful exploitation of this vulnerability enables an attacker to perform full privilege escalation within the KnowStreaming application. By creating rogue administrator accounts or elevating existing low-privileged accounts, an attacker can gain persistent access, exfiltrate sensitive data, or manipulate streaming configurations. This impacts any organization using KnowStreaming for identity management and content control, potentially leading to a complete compromise of the application instance.

## Recommendation

* Patch KnowStreaming to the latest version immediately, as version 3.4.1 and earlier are confirmed vulnerable to CVE-2026-92780.
* Review audit logs for unauthorized user account creation or modification events occurring via the REST API.
* Restrict access to the KnowStreaming REST API endpoints to only known, trusted management IP addresses at the network or web proxy layer.
