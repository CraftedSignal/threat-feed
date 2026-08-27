---
title: Cross-Realm Information Disclosure in OpenRemote Notification API
slug: 2026-08-openremote-info-disclosure
description: OpenRemote versions prior to 1.28.0 contain an information disclosure vulnerability in the Notification REST API that allows authenticated administrators to access sensitive data across all system realms.
date: "2026-08-27T19:10:46Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - OpenRemote
products:
  - OpenRemote
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An authenticated attacker with read:admin privileges within a single realm can exploit this flaw by submitting a zero-parameter GET request to the notification endpoint, resulting in unauthorized access to sensitive notification metadata and message bodies across all system realms.
    confidence_band: high
cves:
  - id: CVE-2026-81679
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81679
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenRemote to version 1.28.0 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-81679 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Restrict read:admin permissions for untrusted accounts
      owner: IT Operations
      addresses: CVE-2026-81679
      evidence: Vulnerability requires existing read:admin credentials
---

OpenRemote versions prior to 1.28.0 are susceptible to a cross-realm information disclosure vulnerability (CVE-2026-81679) within the Notification REST API. This vulnerability stems from improper authorization checks, enabling a tenant administrator with read:admin credentials in one realm to view notification metadata and message bodies belonging to other tenants. By submitting a specifically crafted GET request to the notification endpoint, an attacker can bypass intended realm isolation. This issue is particularly critical for multi-tenant environments where strict data separation is required for compliance and security. The vulnerability allows an attacker to exfiltrate notification content from across the entire instance, potentially leading to the exposure of sensitive configuration details, PII, or internal credentials transmitted via system notifications.

## Impact

Successful exploitation results in the unauthorized collection of cross-tenant notification data. This impacts multi-tenant deployments by breaking tenant isolation boundaries, potentially exposing sensitive message content and metadata to unauthorized administrators. The number of affected deployments is tied to the adoption of OpenRemote versions 1.27.x and earlier in multi-realm configurations.

## Recommendation

* Upgrade all instances of OpenRemote to version 1.28.0 or later to apply the necessary authorization controls.
* Audit logs for administrative access to the notification REST API endpoint, specifically monitoring for frequent GET requests from accounts that should be limited to a single tenant context.
* Review all notification content and templates to ensure that sensitive PII or credentials are not being transmitted via system notifications until the upgrade is completed.
