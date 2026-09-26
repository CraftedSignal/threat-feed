---
title: Authorization Bypass in Capgo Bundle Promotion API
slug: 2026-09-capgo-auth-bypass
description: An incorrect authorization flaw in the Capgo server backend allows users with app-level permissions to bypass per-channel restrictions when promoting bundles due to improper scope handling.
date: "2026-09-26T15:03:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:capgo:capgo:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - api-security
  - cloud
vendors:
  - Capgo
products:
  - Capgo
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: A principal holding app-level channel.promote_bundle (granted by default to the app_developer and app_uploader roles) can therefore promote a bundle to a channel for which an explicit per-channel deny override exists
    confidence_band: high
cves:
  - id: CVE-2026-100627
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100627
action_plan:
  priority: elevated
  owners:
    - SOC
    - DevOps
  immediate_actions:
    - action: Review and audit all Capgo API keys currently configured with 'all' or 'write' access to minimize the blast radius of this bypass
      owner: DevOps
      due: 48h
      evidence: The PUT /bundle endpoint is available to all and write API keys
  mitigation_plan:
    - priority: immediate
      action: Monitor channel promotion logs for unexpected account activity until a vendor-provided patch is released
      owner: SOC
      addresses: CVE-2026-100627
      evidence: The issue allows unauthorized update of public.channels.version
---

Capgo (Cap-go/capgo.app) server backend Supabase functions contain an incorrect authorization vulnerability in the API-key bundle promotion path (CVE-2026-100627). The PUT /bundle endpoint, which is accessible to API keys with "all" and "write" permissions, fails to include the request's channel_id when dispatching to the setChannel function. Consequently, the checkPermission function receives an SQL NULL value for the scope field. Because the RBAC logic evaluates channel-scope overrides only when a channel identifier is present, the system fails to verify explicit per-channel allow or deny configurations. This flaw allows a principal with app-level channel.promote_bundle permissions, typically granted to app_developer or app_uploader roles, to bypass intended restrictions and promote bundles to unauthorized channels, thereby modifying the public.channels.version for that specific channel. The vulnerability is confirmed in commit de66fa51e7ff2f50283cc1455c3d80ab3eb0ae43. No patch is currently available.

## Impact

Successful exploitation allows for the unauthorized promotion of software bundles to production or restricted channels. By bypassing granular per-channel access controls, an attacker can modify the version tracking for any channel associated with an application they have basic access to, potentially leading to unauthorized code distribution or disruption of release cycles for impacted applications.

## Recommendation

Prioritize monitoring and strict access management for Capgo API keys. Since no patch is available, organizations should conduct an audit of all active API keys with "all" or "write" scope to ensure that the risk of unauthorized bundle promotion is managed within the current architecture.
