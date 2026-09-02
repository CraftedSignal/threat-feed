---
title: Authorization Bypass in Craft CMS assets/move-asset Endpoint
slug: 2026-09-craft-cms-auth-bypass
description: Craft CMS versions prior to 5.10.11 contain an authorization bypass in the assets/move-asset endpoint, allowing authenticated users with insufficient permissions to move and delete arbitrary assets by supplying the force=1 parameter.
date: "2026-09-02T13:13:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Craft CMS
products:
  - Craft CMS (< 5.10.11)
cves:
  - id: CVE-2026-84794
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84794
rules:
  - title: Detects CVE-2026-84794 Exploitation - Unauthorized Asset Move Request
    description: Detects POST requests to the assets/move-asset endpoint containing the force=1 parameter, which may indicate an attempt to exploit the authorization bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Craft CMS to version 5.10.11 or later.
      owner: IT Operations
      due: 48h
      evidence: Source states version 5.10.11 contains the fix.
  mitigation_plan:
    - priority: immediate
      action: Patch Craft CMS to 5.10.11.
      owner: IT Operations
      addresses: CVE-2026-84794
      evidence: NVD advisory for CVE-2026-84794.
---

Craft CMS versions before 5.10.11 are vulnerable to an authorization bypass vulnerability (CVE-2026-84794) within the assets/move-asset endpoint. The vulnerability arises when an authenticated user, even without the necessary peer asset permissions, submits a specifically crafted request to move an asset. By supplying the 'force=1' parameter, the attacker can manipulate the move operation to target folders owned by other users. This action can force the deletion of conflicting files already present in the target destination, leading to unauthorized asset replacement and permanent data loss. This flaw highlights a failure in the application's access control logic regarding asset management operations. Organizations utilizing Craft CMS 5.x should upgrade to version 5.10.11 or later to remediate this vulnerability.

## Impact

Successful exploitation allows authenticated, low-privileged users to perform unauthorized asset management actions. This results in the potential destruction of data, modification of content, and the ability to replace files within other users' folders, which can disrupt site operations and compromise data integrity.

## Recommendation

- Upgrade all instances of Craft CMS to version 5.10.11 or later immediately.
- Review web server access logs for anomalous POST requests to the 'assets/move-asset' endpoint.
- Audit user permissions to ensure that only authorized users possess the necessary privileges for asset management.
- Deploy the provided web application detection rule to identify attempts to trigger the vulnerable endpoint with the force parameter.
