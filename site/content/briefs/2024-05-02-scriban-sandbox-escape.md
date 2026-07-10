---
title: Scriban TemplateContext MemberFilter Bypass Vulnerability
slug: 2024-05-02-scriban-sandbox-escape
description: Scriban versions before 7.0.0 are vulnerable to a sandbox escape due to improper caching of type accessors in `TemplateContext`, leading to a `MemberFilter` bypass when a `TemplateContext` is reused, potentially exposing sensitive data.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - scriban
  - sandbox-escape
  - memberfilter-bypass
vendors:
  - Scriban
products:
  - Scriban
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
references:
  - https://github.com/advisories/GHSA-5wr9-m6jw-xx44
rules:
  - title: Detect Scriban TemplateContext Reset Without Member Accessor Clear
    description: Detects code patterns where TemplateContext.Reset() is called without clearing member accessors, indicating potential for MemberFilter bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Scriban Template Rendering with Changing Member Filters
    description: Detects code patterns where a Scriban template is rendered with TemplateContext and MemberFilter is changed without creating new TemplateContext.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Scriban, a .NET templating engine, is vulnerable to a sandbox escape vulnerability affecting versions prior to 7.0.0. This vulnerability arises from the `TemplateContext` caching type accessors without clearing them upon reset. Specifically, the `TemplateContext` caches accessors based on `Type`, but these accessors are created using the `MemberFilter` and `MemberRenamer` active at the time. When a `TemplateContext` is reused with a tightened filter for subsequent renders, Scriban reuses the old accessor, potentially exposing members that should be hidden. This bypass allows unauthorized access or modification of filtered properties or fields, leading to policy bypass across requests, users, or tenants when contexts are pooled. The vulnerability is present in `src/Scriban/TemplateContext.cs` and `src/Scriban/Runtime/Accessors/TypedObjectAccessor.cs`.

## Attack Chain

1. An application initializes a `TemplateContext` with a permissive `MemberFilter`, allowing access to a wide range of object members.
2. The application renders a template using the `TemplateContext`, creating a `TypedObjectAccessor` for a specific type and caching it within the `_memberAccessors` dictionary using the `Type` as the key.
3. The application calls `TemplateContext.Reset()`, which clears most of the context but crucially does *not* clear the `_memberAccessors` cache.
4. The application modifies the `MemberFilter` to be more restrictive, aiming to limit access to specific members.
5. The application renders another template using the same (reused) `TemplateContext`.
6. When the application attempts to access members of the same type as in step 2, Scriban retrieves the cached `TypedObjectAccessor` from `_memberAccessors`.
7. The cached `TypedObjectAccessor` still uses the original, permissive `MemberFilter`, bypassing the newly configured restrictive filter.
8. Sensitive data, which should have been filtered, is exposed or modified, leading to unauthorized access or policy bypass.

## Impact

Successful exploitation of this vulnerability allows unauthorized read or write access to properties and fields that should have been filtered by the `MemberFilter`. This can lead to the exposure of sensitive data, unauthorized modification of application state, and policy bypass across requests, users, or tenants. Applications that rely on `TemplateContext.MemberFilter` for sandboxing or object-exposure policy are particularly vulnerable. The vulnerability affects Scriban versions prior to 7.0.0.

## Recommendation

*   Upgrade to Scriban version 7.0.0 or later to remediate the vulnerability (Affected Packages: nuget/scriban (vulnerable: < 7.0.0)).
*   Avoid reusing `TemplateContext` instances with different `MemberFilter` configurations. Create a new `TemplateContext` for each rendering operation with a distinct `MemberFilter`.
*   Implement server-side checks to validate and sanitize data before rendering it with Scriban to mitigate the impact of potential sandbox escapes.
*   Monitor Scriban template rendering for unexpected data access patterns to detect potential exploitation attempts.
