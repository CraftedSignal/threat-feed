---
title: Authorization Bypass in Yeti RBAC API
slug: 2026-09-yeti-rbac-bypass
description: Yeti versions 2.11.0 and earlier contain an authorization vulnerability in the DELETE /api/v2/rbac/{id} endpoint that allows unauthorized users to delete access control relationships, causing permanent lockout of legitimate object owners.
date: "2026-09-16T21:56:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yeti:yeti:*:*:*:*:*:*:*:*
vendors:
  - Yeti
products:
  - Yeti (<= 2.11.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: The vulnerability allows users with read access to delete access control relationships, enabling them to revoke owner grants and permanently lock legitimate owners out of objects.
    confidence_band: high
cves:
  - id: CVE-2026-92783
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92783
rules:
  - title: Detect CVE-2026-92783 Exploitation - Unauthorized DELETE Request to RBAC API
    description: Detects unauthorized attempts to invoke the DELETE method on the Yeti RBAC API endpoint by low-privileged accounts.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1548.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Yeti to a version greater than 2.11.0
      owner: IT Operations
      due: 48h
      evidence: Yeti through 2.11.0 fails to validate caller permissions.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF to block HTTP DELETE requests to /api/v2/rbac/* for non-administrator sessions
      owner: IT Operations
      addresses: CVE-2026-92783
      evidence: The flaw exists in the DELETE /api/v2/rbac/{id} endpoint.
---

Yeti versions up to and including 2.11.0 contain a critical authorization vulnerability (CVE-2026-92783) within the RBAC API management subsystem. The vulnerability resides in the DELETE /api/v2/rbac/{id} endpoint, which lacks sufficient server-side permission validation. This flaw allows an authenticated attacker possessing only read-only access to successfully invoke the deletion of access control entries for objects they do not own. By exploiting this oversight, an attacker can revoke administrative grants or ownership associations, resulting in a persistent state where legitimate owners are permanently locked out of their objects and denied administrative control. This represents a significant integrity and availability risk for environments utilizing Yeti for access management.

## Impact

Successful exploitation results in unauthorized modification of security policies and permanent denial of service for administrative object management. In multi-tenant or collaborative environments, an attacker with low-privileged read access can effectively neutralize security controls, prevent legitimate administrators from accessing critical data, and disrupt organizational workflows.

## Recommendation

Prioritize the immediate update of all Yeti instances to a patched version beyond 2.11.0. If immediate patching is not feasible, restrict access to the /api/v2/rbac/ endpoint using a web application firewall or reverse proxy to block DELETE methods from unauthorized accounts.
