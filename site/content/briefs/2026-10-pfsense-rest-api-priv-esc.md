---
brief_id: brief-2026-10-21-pfsense-rest-api-priv-esc
event_id: brief-2026-10-21-pfsense-rest-api-priv-esc
revision: 1
activity_at: "2026-10-21T16:06:05Z"
title: 'pfSense-pkg-RESTAPI: Privilege escalation via Scoped HA Settings Sync (CVE-2026-113779)'
slug: 2026-10-pfsense-rest-api-priv-esc
description: Authenticated users with the 'Scoped HA Settings Sync' permission can exploit CVE-2026-113779 in pfSense-pkg-RESTAPI versions prior to 2.9.0 to modify API configuration secrets and achieve full administrative privilege escalation.
date: "2026-10-21T16:06:05Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Awaiting environment validation of patched version.
cpes:
  - cpe:2.3:a:pfsense:pfrest:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - pfsense
  - api-security
vendors:
  - pfSense
products:
  - pfSense-pkg-RESTAPI (< 2.9.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A privilege escalation vulnerability in pfSense-pkg-RESTAPI prior to version 2.9.0 allows authenticated accounts holding the dedicated settings sync permission to modify REST API configuration secrets.
    confidence_band: high
cves:
  - id: CVE-2026-113779
    cvss: 8.8
    kev_status: "false"
references:
  - https://github.com/pfrest/pfSense-pkg-RESTAPI/security/advisories/GHSA-8q8g-9f77-8g8g
  - https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/tag/v2.9.0
  - https://sploitus.com/exploit?id=CVE-2026-113779
  - https://sploitus.com/exploit?id=CVE-2026-113779&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade pfSense-pkg-RESTAPI to v2.9.0
      owner: IT Operations
      due: 24h
      evidence: Vendor release v2.9.0 includes the required patch and hardening measures.
  mitigation_plan:
    - priority: immediate
      action: Revoke api-v2-system-restapi-settings-sync-post privilege from non-admin users
      owner: IT Operations
      addresses: CVE-2026-113779
      evidence: Source workaround documentation
---

The pfSense REST API package (pfSense-pkg-RESTAPI) is vulnerable to a privilege escalation flaw (CVE-2026-113779) in versions prior to 2.9.0. Authenticated users assigned the 'Scoped HA Settings Sync' privilege can interact with the HA settings sync endpoint to modify REST API configuration secrets. This lack of proper access control allows a non-administrative user to elevate their privileges to full administrator. Version 2.9.0 mitigates this by restricting the HA settings sync endpoint to full administrative privileges ('page-all') and removing the sub-administrative sync privilege entirely.

## Impact
Successful exploitation allows a low-privileged authenticated user to elevate their access to full administrator, granting them complete control over the pfSense REST API and the underlying firewall configuration.

## Recommendation
- Upgrade pfSense-pkg-RESTAPI to version 2.9.0 or later immediately.
- If patching is not immediately possible, revoke the 'api-v2-system-restapi-settings-sync-post' privilege from all non-administrative users.
- Restrict access to REST API endpoints to trusted administrator and HA peer IP addresses using REST API Access Control Lists (ACLs) and firewall rules.
