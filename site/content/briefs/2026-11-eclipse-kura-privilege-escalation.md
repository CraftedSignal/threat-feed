---
brief_id: brief-2026-11-10-eclipse-kura-privilege-escalation
event_id: brief-2026-11-10-eclipse-kura-privilege-escalation
revision: 1
activity_at: "2026-11-10T16:59:48Z"
title: 'Eclipse Kura: Authenticated privilege escalation via Wire Service REST API (CVE-2026-113422)'
slug: 2026-11-eclipse-kura-privilege-escalation
description: Eclipse Kura versions 5.0.0 through 5.6.2 contain a vulnerability in the Wire Graph update functionality that allows an authenticated user with low-level administrative permissions to escalate to full administrative control.
date: "2026-11-10T16:59:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:eclipse:kura:5.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:eclipse:kura:5.6.2:*:*:*:*:*:*:*
vendors:
  - Eclipse
products:
  - Kura (5.0.0 through 5.6.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated identity holding only the Wires management permission... can therefore modify the configuration of existing components... This allows escalation to full administrative privileges.
    confidence_band: high
cves:
  - id: CVE-2026-113422
    kev_status: "false"
references:
  - https://github.com/eclipse-kura/kura/security/advisories/GHSA-7pmq-r5px-vgw5
  - https://gitlab.eclipse.org/security/cve-assignment/-/work_items/432
  - https://sploitus.com/exploit?id=CVE-2026-113422&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Eclipse Kura to 5.6.3 or later
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in Eclipse Kura 5.6.3.
  hunt_leads:
    - lead: Identify unusual configuration update requests in web server or REST API access logs targeting security-critical components.
      technique_id: T1068
      data_needed:
        - Web server access logs (URI stem, method, user context)
        - Kura application logs related to configuration updates
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The Wire Graph update functionality... determine whether a configuration update targets a Wire Component, Driver or Asset from the factory identifier supplied in the request.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Eclipse Kura 5.6.3
      owner: IT Operations
      addresses: CVE-2026-113422
      evidence: The issue is fixed in Eclipse Kura 5.6.3.
---

Eclipse Kura versions 5.0.0 through 5.6.2 are vulnerable to an authenticated privilege escalation issue within the Wire Graph update functionality of the Kura Web UI and the Wire Service REST API v1. An authenticated identity with limited permissions (kura.wires.admin or rest.wires.admin) can provide a manipulated factory identifier in a configuration request. The system incorrectly trusts this identifier to determine the target component, allowing the user to modify or replace security-relevant components outside the intended Wire Graph. This vulnerability requires at least one Driver to be installed on the device.

## Impact

Successful exploitation allows an authenticated user with restricted Wires management privileges to gain full administrative control over the Eclipse Kura device or cause operational disruption.

## Recommendation

* Upgrade Eclipse Kura to version 5.6.3 or later immediately to remediate CVE-2026-113422.
* Restrict access to the Kura Web UI and Wire Service REST API to trusted administrative accounts only.
* Audit existing user permissions to ensure the 'kura.wires.admin' and 'rest.wires.admin' roles are assigned only to authorized personnel.
