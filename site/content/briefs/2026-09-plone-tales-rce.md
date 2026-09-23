---
title: Remote Code Execution via TALES Injection in plone.app.portlets
slug: 2026-09-plone-tales-rce
description: Authenticated users can execute arbitrary code in the context of the Plone process by injecting malicious TALES expressions into Classic portlet configurations, exploitable via CVE-2026-57149.
date: "2026-09-23T19:56:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:plone:plone_app_portlets:*:*:*:*:*:*:*:*
tags:
  - rce
  - injection
  - vulnerability
  - web
vendors:
  - Plone
products:
  - plone.app.portlets (>= 7.0.0, <= 7.0.1)
  - plone.app.portlets (>= 6.0.0, <= 6.0.3)
  - plone.app.portlets (>= 5.0.0, <= 5.0.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A user able to add or edit a Classic portlet could supply a crafted value that escapes simple path traversal and is evaluated as arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-57149
    cvss: 9.9
references:
  - https://github.com/advisories/GHSA-rr49-f9g6-c9r5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57149
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: 'Upgrade plone.app.portlets to patched versions: 7.0.2 (6.2), 6.0.4 (6.1), or 5.0.8 (6.0).'
      owner: IT Operations
      due: 24h
      evidence: Source advisory requires these versions to mitigate CVE-2026-57149.
  mitigation_plan:
    - priority: immediate
      action: Remove plone.app.portlets.ManageOwnPortlets permission from untrusted roles.
      owner: IT Operations
      addresses: CVE-2026-57149
      evidence: Advisory lists permission restriction as a valid workaround.
---

The Classic portlet component (plone.app.portlets) within Plone is vulnerable to Remote Code Execution (RCE) via a TALES (Template Attribute Language Expression Syntax) injection flaw, tracked as CVE-2026-57149. The vulnerability exists because the component improperly treats user-supplied template or macro fields as part of a TALES path expression, which is then processed by the TAL path() helper. 

An authenticated user with permissions to configure a Classic portlet can supply a crafted input that escapes basic path structures to execute arbitrary code within the server-side process. By default, regular users often possess the ability to add or edit portlets on their personal dashboards, significantly expanding the attack surface for internal privilege escalation. This vulnerability affects Plone 6.0, 6.1, and 6.2 versions via specific versions of the plone.app.portlets package.

## Impact

Successful exploitation allows an authenticated user to achieve full code execution on the server hosting the Plone instance. This results in complete system compromise, unauthorized data access, and privilege escalation from a standard user to the security context of the Plone process, impacting the confidentiality, integrity, and availability of the affected Plone installation.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Upgrade the affected package to the patched versions immediately:
 - For Plone 6.2: Upgrade to `plone.app.portlets` 7.0.2.
 - For Plone 6.1: Upgrade to `plone.app.portlets` 6.0.4.
 - For Plone 6.0: Upgrade to `plone.app.portlets` 5.0.8.
- If immediate patching is not feasible, restrict the `plone.app.portlets.ManageOwnPortlets` permission from untrusted roles to prevent exploitation attempts by standard users.
- Audit administrative logs for unauthorized modifications to Classic portlets as a hunt for potential exploitation attempts targeting CVE-2026-57149.
