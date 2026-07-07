---
title: 'Scriban Template Engine Vulnerability: Arbitrary CLR Property Writes (Mass Assignment & Setter Bypass)'
slug: 2026-07-scriban-mass-assignment-cwe-915-cwe-284
description: The Scriban templating engine, specifically its `TypedObjectAccessor`, allows template code to write to arbitrary CLR object properties, including those with `private set`, `internal set`, and `init` modifiers, effectively bypassing intended C# access restrictions. This mass assignment (CWE-915) and access-modifier bypass (CWE-284) vulnerability can lead to unauthorized modification of sensitive host object properties, such as changing `user.is_admin = true`, with changes persisting after template rendering, affecting Scriban versions up to and including 7.2.1, with the `init` bypass specifically impacting .NET 5+.
date: "2026-07-06T17:38:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - templating-engine
  - mass-assignment
  - access-control-bypass
  - vulnerability
  - csharp
  - dotnet
vendors:
  - Scriban
products:
  - Scriban <= 7.2.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability allows template code to write to arbitrary CLR properties, including those that could control user privileges (e.g., `{{ user.is_admin = true }}`).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Properties the developer deliberately restricted (e.g., `private set`, `internal set`, `init`) are also writable, because reflection ignores C# accessibility, bypassing intended security controls.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7jvp-hj45-2f2m
  - https://learn.microsoft.com/dotnet/api/system.reflection.propertyinfo.setvalue
  - https://learn.microsoft.com/dotnet/csharp/language-reference/proposals/csharp-9.0/init
  - https://cwe.mitre.org/data/definitions/915.html
  - https://cwe.mitre.org/data/definitions/284.html
---

A critical vulnerability exists in the Scriban templating engine (versions <= 7.2.1) where its `TypedObjectAccessor` component permits template code to arbitrarily write to properties of Common Language Runtime (CLR) objects pushed into a `TemplateContext`. This flaw encompasses two primary weaknesses: mass assignment of public setters (CWE-915) and an access-modifier bypass (CWE-284), which allows templates to modify properties declared with `private set`, `internal set`, or `init` modifiers. The `TypedObjectAccessor` fails to perform `CanWrite` or setter-visibility checks, enabling reflective invocation of property setters. This means that a malicious template can alter sensitive data or application state, such as elevating privileges (e.g., setting `user.is_admin` to `true`) directly on the host application's live objects. The changes persist even after the template rendering completes. The `init` keyword bypass specifically affects applications running on .NET 5.0 and later versions, while `private set` and `internal set` bypasses affect all supported runtimes.

## Attack Chain

1.  **Application Embeds Host Object:** A host .NET application initializes a Scriban `TemplateContext` and pushes a sensitive CLR object (e.g., a `User` object) into it using a `ScriptObject` (e.g., `so["user"] = currentUser; context.PushGlobal(so);`).
2.  **Malicious Template Content:** An attacker introduces or manipulates Scriban template code executed by the host application to include an assignment operation targeting a property of the embedded CLR object (e.g., `{{ user.IsAdmin = true }}`, `{{ order.TotalPrice = 0 }}`, or `{{ config.SensitiveSetting = 'malicious_value' }}`).
3.  **Template Execution Initiated:** The host application calls a method like `Render()` on the Scriban template, triggering its execution.
4.  **Vulnerable Accessor Invocation:** During template execution, when the malicious assignment is encountered, Scriban's internal dispatch mechanism calls `TypedObjectAccessor.TrySetValue` for the targeted property.
5.  **Setter Visibility Bypass:** The `TypedObjectAccessor.TrySetValue` method, specifically in lines 108–123 of `TypedObjectAccessor.cs`, proceeds without verifying the `CanWrite` status of the property or checking the visibility (e.g., `private set`, `internal set`) or `init` status of its setter.
6.  **Reflection Property Modification:** The vulnerability allows the `propertyAccessor.SetValue` method to be directly invoked via reflection, bypassing the standard C# access modifiers and developer intent for restricted properties.
7.  **Persistent Property Alteration:** The live CLR object instance within the host application has its property value permanently altered. These changes persist after the template rendering operation has completed.
8.  **Unauthorized Data Modification/Privilege Escalation:** The host application continues execution with the maliciously altered object property, leading to unintended consequences such as unauthorized privilege escalation, data corruption, or configuration changes.

## Impact

The vulnerability in Scriban can lead to severe data integrity issues and potential privilege escalation within host applications. By exploiting this flaw, attackers can bypass critical C# access modifiers (`private set`, `internal set`, `init`) and modify any CLR object property exposed to the template engine. This could result in unauthorized administrative access if a `user.is_admin` property is toggled, financial manipulation if `order.total_price` is set to zero, or critical system configuration changes. The altered state persists in the live application object, meaning the impact is immediate and enduring until the application state is reset or the object is reloaded, compromising the application's security and reliability.

## Recommendation

*   Review all Scriban templates and the host application's interaction with `TemplateContext` to identify and restrict the types of CLR objects exposed.
*   As no patch currently exists, implement custom controls as described in the remediation "Fix 2" in the reference advisory: add a `MemberWriteFilter` on `TemplateContext` or use a `[ScriptMemberReadOnly]` attribute to explicitly control write access to properties.
*   Regularly monitor the Scriban project's GitHub repository or NuGet feed for a patched version (`nuget/Scriban`) and apply it immediately once available.
*   Review application code for `TypedObjectAccessor` usage and its implications, paying close attention to sensitive properties that are pushed into the `TemplateContext`.
