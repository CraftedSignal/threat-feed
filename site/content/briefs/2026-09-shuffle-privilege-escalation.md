---
title: Cross-Tenant Privilege Escalation in Shuffle
slug: 2026-09-shuffle-privilege-escalation
description: Shuffle through version 2.2.1 is vulnerable to a cross-tenant privilege escalation flaw in the HandleApiGeneration endpoint that allows an authenticated administrator to reset and steal API keys from other tenants.
date: "2026-09-16T19:51:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:shuffle:shuffle_through:2.2.1:*:*:*:*:*:*:*
vendors:
  - Shuffle
products:
  - Shuffle through (2.2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers with admin privileges in one organization can supply arbitrary user IDs to generate valid API keys for users in different organizations.
    confidence_band: high
cves:
  - id: CVE-2026-92716
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92716
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit logs for unauthorized access to the HandleApiGeneration endpoint.
      owner: SOC
      due: 24h
      evidence: CVE-2026-92716 vulnerability description.
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply updates for Shuffle through as soon as they become available to remediate CVE-2026-92716.
      owner: IT Operations
      addresses: CVE-2026-92716
      evidence: NVD vulnerability disclosure for CVE-2026-92716.
---

Shuffle through version 2.2.1 contains a severe security vulnerability (CVE-2026-92716) that facilitates cross-tenant privilege escalation. The vulnerability resides within the HandleApiGeneration endpoint. An attacker who has already obtained administrator privileges within one Shuffle tenant can leverage this endpoint to perform unauthorized actions against other organizations using the platform. Specifically, by supplying arbitrary user IDs to the vulnerable endpoint, an administrator can trigger a reset of API keys for users belonging to different organizations. The endpoint then returns the generated keys to the attacker, effectively granting them full programmatic access to the victim's account across tenant boundaries. This flaw represents a critical security risk for multi-tenant environments where the isolation of administrative control is expected. 

## Impact

The exploitation of this vulnerability allows for complete cross-tenant account takeover. An attacker can access sensitive data, modify workflow configurations, and perform unauthorized actions within the victim's organization, bypassing the intended logical isolation between tenants.

## Recommendation

Prioritize the investigation of administrative account logs to identify any requests to the HandleApiGeneration endpoint referencing User IDs belonging to different organization identifiers. If available, restrict access to administrative API endpoints via network-level controls or WAF rules to known trusted administrative IP addresses. Immediately upgrade all Shuffle through instances to a patched version once released by the vendor to eliminate the underlying logic flaw.
