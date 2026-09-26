---
title: Authorization Bypass in capgo.app via Channel Permission Overrides
slug: 2026-09-capgo-auth-bypass
description: A vulnerability in capgo.app allows authenticated administrators to bypass organization boundaries by assigning channel-specific permissions to arbitrary external user UUIDs.
date: "2026-09-26T15:02:09Z"
lastmod: "2026-09-26T19:00:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cap_go:capgo_app:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - cloud-security
  - privilege-escalation
  - vulnerability
  - cloud
  - ota-updates
  - rce
  - exfiltration
  - rbac-flaw
vendors:
  - Cap-go
  - Capgo
products:
  - capgo.app
  - capgo.app (<= 12.129.0)
  - capgo.app (< 12.267.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers with admin privileges can insert override rows with arbitrary external user UUIDs to grant channel-scoped permissions to users outside the organization.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with appropriate API or user permissions can supply malicious file data via public.app_versions.manifest for versions configured with 'r2-direct' storage.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This allows an authenticated organization administrator to arbitrarily add existing users to their organization with 'admin' privileges, bypassing all intended access control mechanisms.
    confidence_band: high
cves:
  - id: CVE-2026-100617
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100617
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100619
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100622
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100623
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100615
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review organization logs for unauthorized channel permission changes
      owner: SOC
      due: 24h
      evidence: Source documentation of arbitrary UUID injection via channel_permission_overrides
  mitigation_plan:
    - priority: immediate
      action: Upgrade capgo.app to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-100617
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-09-26T15:02:34Z"
    level: L2
    summary: added coverage for capgo.app
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100619
  - at: "2026-09-26T15:02:41Z"
    level: L2
    summary: added coverage for capgo.app (<= 12.129.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100622
  - at: "2026-09-26T17:00:02Z"
    level: L2
    summary: added coverage for capgo.app
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100623
  - at: "2026-09-26T19:00:10Z"
    level: L2
    summary: added coverage for capgo.app (< 12.267.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100615
---

Cap-go capgo.app contains a critical authorization vulnerability (CVE-2026-100617) stemming from improper input validation within the `channel_permission_overrides` function. The application fails to verify that user principals referenced in permission overrides actually belong to the target organization. This allows an authenticated administrator (at either the application or organization level) to maliciously associate arbitrary external user UUIDs with internal channel permissions. An attacker can leverage this flaw to grant sensitive permissions, such as `channel.promote_bundle`, to external entities that should have no access to the organization's private channels. This creates a significant risk of unauthorized access to sensitive deployment bundles and internal processes.

## Impact

Successful exploitation allows for the unauthorized granting of administrative channel permissions to users outside of the intended organization. This can lead to unauthorized modification of deployment bundles, unauthorized channel management, and potential supply chain compromise if external users gain the ability to influence code or asset promotion within the victim organization's infrastructure.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Audit organizational audit logs for suspicious additions to `channel_permission_overrides` where the assigned UUID does not correspond to an existing member of the organization.
- Review all current permission overrides within the capgo.app management interface to identify and remove entries involving unrecognized or external UUIDs.
- Update capgo.app to the latest version that implements strict validation of principal organization membership.
