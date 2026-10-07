---
title: 'CVE-2026-107270: IDOR Vulnerability in Gophish API'
slug: 2026-10-gophish-idor
description: Gophish versions 0.12.1 and earlier are vulnerable to an Insecure Direct Object Reference (IDOR) flaw allowing authenticated users to modify or hijack unauthorized administrative objects.
date: "2026-10-07T17:07:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gophish:gophish:*:*:*:*:*:*:*:*
tags:
  - idor
  - api-vulnerability
  - privilege-escalation
vendors:
  - Gophish
products:
  - Gophish (<= 0.12.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An insecure direct object reference vulnerability allows authenticated users to take over other users' groups, templates, landing pages and sending profiles.
    confidence_band: high
cves:
  - id: CVE-2026-107270
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107270
rules:
  - title: Detect CVE-2026-107270 Exploitation - API Object Modification
    description: Detects potential IDOR exploitation via POST requests to Gophish API endpoints used for object management.
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
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy web application firewall rules or access control lists to restrict access to /api/ endpoints in Gophish
      owner: IT Operations
      due: 24h
      evidence: Source identifies API endpoints as the vector for CVE-2026-107270
  enrichment_needed:
    - item: Monitor for upstream patches from the Gophish repository
      owner: CTI
      reason: No fixed version is currently listed
      evidence: NVD record status
  hunt_leads:
    - lead: Search web logs for POST requests to /api/ paths with sequential integer IDs
      technique_id: T1068
      data_needed:
        - Web access logs (cs-method, cs-uri-stem)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies object ID manipulation in API requests
  mitigation_plan:
    - priority: medium_term
      action: Upgrade Gophish once a version > 0.12.1 is released
      owner: IT Operations
      addresses: CVE-2026-107270
      evidence: NVD record indicates vulnerability persists through 0.12.1
---

Gophish versions 0.12.1 and earlier contain an insecure direct object reference (IDOR) vulnerability that allows an authenticated user to perform unauthorized modifications to critical system objects. By manipulating the sequential ID parameter within POST requests directed at specific API endpoints, an attacker can overwrite or reassign existing groups, email templates, landing pages, and SMTP sending profiles. This vulnerability effectively allows an attacker to lock out legitimate users from their configuration assets and potentially expose sensitive recipient lists associated with those campaigns. Because Gophish is frequently used for internal phishing simulations, the impact of this vulnerability includes potential cross-departmental data leakage and the compromise of simulated phishing campaign integrity. Organizations using self-hosted Gophish instances are advised to restrict access to the API and monitor for suspicious administrative object modifications until a patched version is available.

## Impact

The vulnerability allows for the unauthorized takeover of administrative objects, leading to the lockout of legitimate users and the exposure of sensitive recipient data. Successful exploitation permits an attacker to alter the configuration of ongoing simulations or use another user's SMTP profiles to send malicious email, undermining the platform's security controls.

## Recommendation

- Monitor web server access logs for anomalous POST requests to API paths (/api/groups/, /api/templates/, /api/pages/, /api/smtp/) that reference ID parameters inconsistent with the authenticated user session.
- Limit access to the Gophish web interface and API to trusted administrative subnets via firewall rules.
- Audit existing Gophish configurations for unauthorized changes to SMTP profiles or unexpected user associations.
- Patch Gophish as soon as the vendor releases a version addressing CVE-2026-107270.
