---
title: Improper URL Validation in Backstage Catalog Entity Placeholder Resolution
slug: 2026-10-backstage-url-validation
description: An authenticated user can exploit improper URL validation in Backstage plugin-catalog-backend to access unauthorized resources outside the intended source repository via crafted catalog entity placeholder directives.
date: "2026-10-07T22:55:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:backstage:plugin-catalog-backend:*:*:*:*:*:*:*:*
vendors:
  - Backstage
products:
  - plugin-catalog-backend (< 3.9.1)
cves:
  - id: CVE-2026-106498
    cvss: 7.7
references:
  - https://github.com/advisories/GHSA-qgvj-qcf8-xq73
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @backstage/plugin-catalog-backend to version 3.9.1
      owner: IT Operations
      due: 48h
      evidence: Patched in @backstage/plugin-catalog-backend version 3.9.1
  mitigation_plan:
    - priority: immediate
      action: Restrict scope of integration credentials to the minimum necessary repositories
      owner: Security Engineering
      addresses: CVE-2026-106498
      evidence: Limit the scope of integration credentials to only the repositories that Backstage needs to access
---

Backstage version 3.9.1 and earlier, specifically within the @backstage/plugin-catalog-backend package, contains a vulnerability identified as CVE-2026-106498. The flaw arises from insufficient validation of URLs used during the resolution of catalog entity placeholders. An authenticated user with the ability to create or edit catalog entities can manipulate these placeholder directives to point toward internal or external resources that should be inaccessible to them. 

If the Backstage instance is configured with integration credentials, such as broad GitHub tokens, these credentials may be implicitly used to fetch data from resources outside the intended source repository. This behavior increases the risk of unauthorized data disclosure, as the application fails to enforce appropriate path or domain boundaries during the placeholder resolution process. Defenders should prioritize updating the plugin to version 3.9.1 and reviewing the scope of all configured integration credentials to follow the principle of least privilege.

## Impact

The vulnerability affects users of the Backstage catalog who have permissions to manage entity definitions. Successful exploitation can lead to unauthorized access to sensitive internal data or repository content that the attacker would not otherwise be permitted to view, depending on the scope of the integration tokens assigned to the Backstage service.

## Recommendation

- Upgrade the `@backstage/plugin-catalog-backend` package to version 3.9.1 or later to remediate CVE-2026-106498.
- Review and restrict the scope of integration credentials (such as GitHub, GitLab, or Bitbucket tokens) assigned to the Backstage backend to limit access to only required repositories.
- Audit existing catalog entity definitions for suspicious placeholder directives that reference unauthorized internal or external endpoints.
