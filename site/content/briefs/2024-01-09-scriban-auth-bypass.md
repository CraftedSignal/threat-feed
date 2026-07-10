---
title: Scriban TemplateContext Reset Authorization Bypass Vulnerability
slug: 2024-01-09-scriban-auth-bypass
description: Scriban versions before 7.0.0 have an authorization bypass vulnerability due to a stale include cache surviving TemplateContext.Reset(), potentially serving previously authorized content to subsequent renders in applications reusing TemplateContext objects with request-dependent ITemplateLoaders.
date: "2024-01-09T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - scriban
  - template-injection
  - authorization-bypass
vendors:
  - Scriban
products:
  - Scriban
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-x6m9-38vm-2xhf
rules:
  - title: Detect Scriban TemplateContext Reuse with Request-Dependent Loader
    description: Detects potential Scriban template authorization bypass by identifying code patterns where TemplateContext is reused after Reset() with a request-dependent ITemplateLoader.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Scriban Template Include Function Usage
    description: Detects use of the Scriban 'include' function which is necessary for this authorization bypass.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Scriban, a .NET templating engine, is vulnerable to an authorization bypass issue affecting applications that reuse `TemplateContext` objects. Specifically, versions prior to 7.0.0 do not properly clear the `CachedTemplates` collection when `TemplateContext.Reset()` is called. This can lead to a situation where an `ITemplateLoader` that resolves content based on request-specific state (e.g., user identity, tenant context) serves a stale, previously authorized template to subsequent renders, even after the context is reset. This bypass occurs because the `include` function retrieves templates from the cache without re-evaluating authorization, potentially leaking sensitive data across requests or tenants. This vulnerability could be exploited in multi-tenant or permission-sensitive applications using Scriban templates.

## Attack Chain

1. An application initializes a `TemplateContext` object and configures an `ITemplateLoader` that resolves template content based on the current request or user context.
2. A user (e.g., an administrator) makes a request that causes the `ITemplateLoader` to load a privileged template (e.g., "admin_profile.scriban") into the `TemplateContext`.
3. The `include` function is used within the main template to load the privileged template. The compiled template is then cached in `CachedTemplates`.
4. The application calls `TemplateContext.Reset()` in an attempt to clear the context for reuse. However, `CachedTemplates` is not cleared during this reset operation.
5. A different user (e.g., a regular user) makes a subsequent request that reuses the same `TemplateContext` object.
6. The `include` function is called again, attempting to load a template.
7. The `TemplateContext` retrieves the previously cached, privileged template from `CachedTemplates` without calling `ITemplateLoader.Load()` again, bypassing the intended authorization check.
8. The regular user is served the content of the administrator's template, leading to information disclosure.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to sensitive information or functionality in applications using Scriban templating. The primary impact is cross-render data isolation issues, where previously authorized template content can be leaked across different requests, users, or tenants. This can lead to the exposure of sensitive data, privilege escalation, or other security breaches, depending on the content of the leaked templates. Applications that pool or reuse `TemplateContext` objects, call `Reset()` between requests, use `include` for template inclusion, and resolve included content based on request-specific state are vulnerable.

## Recommendation

*   Upgrade to Scriban version 7.0.0 or later, where this vulnerability is resolved.
*   If upgrading is not immediately feasible, avoid reusing `TemplateContext` objects across different requests or user sessions. Create a new `TemplateContext` for each request.
*   Review and audit existing Scriban templates and `ITemplateLoader` implementations to ensure that sensitive data is not inadvertently exposed through template inclusion.
*   Implement additional authorization checks within the templates themselves to verify user permissions before displaying sensitive data, even if the `TemplateLoader` is compromised.
*   Monitor the usage of `TemplateContext.Reset()` in your application and ensure that it is used correctly and does not lead to unintended data leakage.
