---
title: Authorization Bypass in Chroma via Tenant Isolation Failure
slug: 2026-09-chroma-auth-bypass
description: Chroma versions 1.5.9 and earlier are vulnerable to an authorization bypass allowing authenticated users to access, modify, and delete cross-tenant data by manipulating collection identifiers.
date: "2026-09-16T21:56:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:chroma:chroma:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authorization-bypass
  - chroma
vendors:
  - Chroma
products:
  - Chroma (<= 1.5.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An authenticated attacker can access collections from other tenants by knowing the collection identifier.
    confidence_band: high
cves:
  - id: CVE-2026-92782
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92782
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Chroma to a patched version beyond 1.5.9
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions through 1.5.9
  hunt_leads:
    - lead: Identify requests where the authenticated tenant context does not match the accessed collection resource
      technique_id: T1592
      data_needed:
        - Web server access logs or application telemetry
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows accessing other tenants by bypassing authorization checks
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest secure version
      owner: IT Operations
      addresses: CVE-2026-92782
      evidence: Chroma 1.5.9 and earlier are affected
---

Chroma, a vector database, contains a critical authorization flaw in versions up to and including 1.5.9. The vulnerability arises from a failure to validate tenant and database segments when the application resolves collections. Because the system does not enforce strict tenant isolation during the request resolution process, an authenticated attacker who is aware of a collection identifier belonging to another tenant can interact with that collection as if they were authorized. This flaw allows unauthorized read, update, and delete operations on foreign data, effectively breaking the multi-tenancy model. Attackers can reach these foreign collections by issuing requests under their own legitimate tenant path, circumventing the intended security boundaries. Given the role of vector databases in RAG (Retrieval-Augmented Generation) architectures, this vulnerability could lead to the exposure of sensitive proprietary or private documents indexed within unauthorized collections.

## Impact

Successful exploitation allows for unauthorized information disclosure, unauthorized modification of records, and data destruction across tenant boundaries. This impact is significant for multi-tenant deployments, such as SaaS providers or enterprise environments managing multiple teams' data in a single Chroma cluster. The scope is limited to authenticated users of the platform, who can leverage their existing access to escalate their reach to any collection for which they can determine the identifier.

## Recommendation

- Upgrade all Chroma deployments to a version beyond 1.5.9 immediately to incorporate required tenant and database segment validation.
- Review access logs for an abnormal frequency of requests targeting collection identifiers not typically associated with the requesting tenant ID.
- Implement monitoring at the API gateway layer to validate that the tenant ID present in the authenticated session matches the tenant context requested within the URI or query parameters for collection operations.
