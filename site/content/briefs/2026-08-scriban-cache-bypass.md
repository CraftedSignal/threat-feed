---
title: Authorization Bypass in Scriban via Stale Template Cache
slug: 2026-08-scriban-cache-bypass
description: Scriban versions before 7.0.0 fail to clear the CachedTemplates dictionary during TemplateContext.Reset(), potentially allowing unauthorized access to template content across reused contexts.
date: "2026-08-16T14:26:38Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - Scriban
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can exploit request-dependent ITemplateLoader implementations to access previously authorized template content from earlier renders.
    confidence_band: med
cves:
  - id: CVE-2026-74791
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74791
  - https://github.com/scriban/scriban/security/advisories/GHSA-x6m9-38vm-2xhf
  - https://www.vulncheck.com/advisories/scriban-before-authorization-bypass-via-stale-include-cache
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Patch Scriban to version 7.0.0 in all production .NET applications.
      owner: IT Operations
      due: 72h
      evidence: Scriban version 7.0.0 addresses the cache clearing issue.
  mitigation_plan:
    - priority: immediate
      action: Review custom ITemplateLoader implementations for reliance on TemplateLoader.Load() for authorization.
      owner: Application Security
      addresses: CVE-2026-74791
      evidence: The advisory notes the vulnerability impacts request-dependent ITemplateLoader implementations.
---

Scriban, a popular templating engine for .NET, contains a vulnerability (CVE-2026-74791) in versions prior to 7.0.0. The issue stems from the failure to properly clear the `CachedTemplates` dictionary when the `TemplateContext.Reset()` method is invoked. This flaw allows cached templates to persist across different rendering contexts. In applications where `ITemplateLoader` implementations are request-dependent, this behavior can be leveraged by an attacker to access template content that was intended for a different, potentially more privileged user or request context. Because the template is retrieved from the stale cache, the `TemplateLoader.Load()` method is not re-triggered, bypassing intended authorization checks that would typically occur during the loading phase. This vulnerability poses a significant risk of unauthorized information disclosure in multi-tenant or request-heavy applications.

## Impact

The vulnerability allows for unauthorized access to sensitive information by serving cached template content across security boundaries. If an application relies on per-request authorization during the loading of templates, an attacker may be able to view content rendered for other users. This vulnerability is rated as high severity due to the potential for unauthorized data access without requiring user interaction or authentication.

## Recommendation

1. Upgrade all instances of the Scriban library to version 7.0.0 or higher to ensure the `CachedTemplates` dictionary is correctly reset.
2. Audit applications using Scriban that implement custom `ITemplateLoader` logic, specifically checking if authorization checks are performed only during the `Load()` method, as this will be bypassed for cached templates.
3. Monitor application logs for anomalous template rendering activity or unexpected data access patterns in environments leveraging reused `TemplateContext` objects.
