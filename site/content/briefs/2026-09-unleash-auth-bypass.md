---
title: Authorization Bypass and IDOR Vulnerabilities in Unleash Admin API
slug: 2026-09-unleash-auth-bypass
description: Multiple authorization vulnerabilities, including a missing 'await' on a permission check, allow authenticated users to perform unauthorized actions and access sensitive configuration data across projects in Unleash server versions prior to 8.0.3.
date: "2026-09-23T01:55:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:unleash:unleash:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - authorization-bypass
  - idor
  - privilege-escalation
vendors:
  - Unleash
products:
  - unleash-server (< 8.0.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The missing await causes the permission check to evaluate as truthy, allowing any authenticated user to modify segment assignments.
    confidence_band: high
cves:
  - id: CVE-2026-77426
references:
  - https://github.com/advisories/GHSA-72h8-wp98-7hch
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77426
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade unleash-server to 8.0.3 or later
      owner: IT Operations
      due: 24h
      evidence: GHSA-72h8-wp98-7hch recommends version 8.0.3
  hunt_leads:
    - lead: Unauthorized POST requests to /api/admin/segments/strategies
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this specific endpoint as the location of the critical authorization bypass.
  mitigation_plan:
    - priority: immediate
      action: Patch unleash-server to version 8.0.3
      owner: IT Operations
      addresses: CVE-2026-77426
      evidence: Source identifies 8.0.3 as the fixed version.
---

Unleash server versions prior to 8.0.3 are vulnerable to several critical and medium-severity authorization flaws within the admin API. The most significant issue, tracked as CVE-2026-77426, involves a failure to use the 'await' keyword when calling an asynchronous permission check in `segment-controller.ts`. Because the call returns a Promise, which is truthy, the authorization logic defaults to granting access regardless of the user's actual permissions. This flaw allows any authenticated user to modify segment assignments on any strategy across all projects.

In addition to the primary authorization bypass, the Unleash admin API contains multiple Insecure Direct Object Reference (IDOR) vulnerabilities. These flaws permit authenticated attackers to bypass project boundaries to read variant configurations, retrieve strategy details, leak environment information, and modify tags. These issues stem from a failure to validate project ownership or cross-reference parameters against authorized project scopes during API requests. Organizations running affected versions are exposed to unauthorized information disclosure and potential configuration tampering.

## Impact

Successful exploitation allows any authenticated user to gain elevated privileges, enabling them to modify feature strategy configurations and perform cross-project read/write operations. This leads to unauthorized access to feature variant definitions, internal strategy details, and project tagging structures. These vulnerabilities undermine the security posture of feature management systems, potentially allowing an attacker to manipulate application behavior or exfiltrate sensitive configuration information across an entire organization's feature toggle environment.

## Recommendation

- Upgrade Unleash server to version 8.0.3 or later immediately to resolve CVE-2026-77426 and associated IDOR vulnerabilities.
- Review audit logs for unauthorized administrative activity, particularly involving the `/api/admin/segments/strategies` endpoint, starting from the time of deployment of the vulnerable version.
- Implement restrictive network access controls to ensure that only authorized internal systems and personnel can access the Unleash admin API.
