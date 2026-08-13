---
title: Authorization Bypass in SiYuan Development Branch
slug: 2026-08-siyuan-auth-bypass
description: The SiYuan development branch contains an authorization bypass vulnerability in the /api/av/getAttributeViewSearchTarget endpoint, allowing unauthenticated users to access restricted database content.
date: "2026-08-13T12:54:56Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - SiYuan
products:
  - SiYuan (Development Branch)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Given a database identifier taken from a published page and a keyword, an anonymous reader can query the endpoint to retrieve matching database row content.
    confidence_band: high
cves:
  - id: CVE-2026-73608
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73608
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory all SiYuan instances to ensure no development branches are deployed.
      owner: IT Operations
      due: 48h
      evidence: The vulnerability is isolated to the development branch.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or replace instances running development branches with stable version v3.7.4 or later.
      owner: IT Operations
      addresses: CVE-2026-73608
      evidence: Patched in v3.7.4
---

A missing authorization check has been identified in the SiYuan development branch at the /api/av/getAttributeViewSearchTarget endpoint (introduced by commit 9b8e8956f). The vulnerability allows anonymous users to query database content on published pages by providing a database identifier and a keyword. Because the endpoint registers only with 'CheckAuth' but lacks essential 'CheckReadonly', 'publish-access', or 'encrypted-notebook' gating, it effectively bypasses row-level security and filtering mechanisms designed to protect sensitive data.

While the base score for this vulnerability is 8.6, it is important to note that this flaw is restricted to the development branch and does not affect stable releases such as v3.7.3 or the current master branch. The issue was patched in v3.7.4. Defenders should ensure no development branches are deployed in production environments, as these versions may expose internal APIs to external exposure that are not gated for public access.

## Impact

Successful exploitation allows an unauthenticated, remote attacker to exfiltrate database content that should otherwise be withheld by the application's native publish-access filters. This results in unauthorized disclosure of sensitive data managed within SiYuan database views.

## Recommendation

- Ensure that only stable, production-ready versions (v3.7.3 or v3.7.4) of SiYuan are deployed in your environment.
- Audit infrastructure to identify and decommission any instances running development branch builds of SiYuan.
- Monitor webserver logs for unauthorized access patterns or unexpected requests to the /api/av/getAttributeViewSearchTarget endpoint.
