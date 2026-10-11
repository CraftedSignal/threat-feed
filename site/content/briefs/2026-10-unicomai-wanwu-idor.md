---
title: UnicomAI Wanwu IDOR Vulnerability
slug: 2026-10-unicomai-wanwu-idor
description: UnicomAI Wanwu before 0.6.3 contains an insecure direct object reference vulnerability (CVE-2026-108853) that allows authenticated attackers to delete unauthorized tenants' applications.
date: "2026-10-11T16:02:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:unicomai:wanwu:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - idor
  - impact
vendors:
  - UnicomAI
products:
  - Wanwu (< 0.6.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Attackers can send requests to DELETE /v1/appspace/app with guessed sequential assistant IDs to permanently delete victims' applications, workflows, conversations, and associated data.
    confidence_band: high
cves:
  - id: CVE-2026-108853
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108853
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade UnicomAI Wanwu to 0.6.3 or later
      owner: IT Operations
      due: 48h
      evidence: UnicomAI Wanwu before 0.6.3 contains an insecure direct object reference vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 0.6.3 or later
      owner: IT Operations
      addresses: CVE-2026-108853
      evidence: UnicomAI Wanwu before 0.6.3 contains an insecure direct object reference vulnerability.
---

UnicomAI Wanwu versions prior to 0.6.3 contain an insecure direct object reference (IDOR) vulnerability, tracked as CVE-2026-108853. This vulnerability enables an authenticated user with low privileges to delete agent or RAG applications belonging to other tenants. By manipulating the 'appId' parameter within specific API requests, an attacker can target other users' infrastructure. The vulnerability resides in the application's authorization logic, which fails to validate whether the requesting user has the appropriate permissions to perform delete operations on resources belonging to different tenant accounts. This flaw poses a significant risk to data integrity and platform availability, as it can be used to permanently erase workflows, conversation histories, and agent configurations across the multi-tenant environment.

## Impact

Successful exploitation results in the permanent deletion of victims' applications, associated workflows, and conversation data. As the vulnerability allows for sequential ID guessing, an attacker could programmatically iterate through target IDs to cause large-scale data destruction within the platform, affecting potentially all tenants on a vulnerable instance.

## Recommendation

* Upgrade UnicomAI Wanwu to version 0.6.3 or later immediately to resolve the flawed authorization logic in the /v1/appspace/app endpoint.
* Audit web server logs for high-frequency or anomalous DELETE requests to the /v1/appspace/app endpoint originating from low-privileged accounts.
* Implement strict request rate limiting and monitoring for administrative or destructive API actions to detect and mitigate potential mass-deletion attempts.
