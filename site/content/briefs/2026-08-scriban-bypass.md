---
title: Access-Modifier Bypass in Scriban
slug: 2026-08-scriban-bypass
description: Scriban versions prior to 7.2.2 contain an access-modifier bypass in TypedObjectAccessor that allows unauthorized modification of private, internal, or init-only CLR object properties via template injection.
date: "2026-08-16T14:25:30Z"
lastmod: "2026-08-16T14:26:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - dot-net
  - template-injection
  - access-control
  - sandbox-bypass
  - cve-2026-74790
  - .net
  - denial-of-service
  - scriban
  - cve-2026-74783
vendors:
  - Scriban
products:
  - Scriban
  - Scriban (3.0.0 through 7.2.5)
  - Scriban (6.6.0-7.2.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This flaw allows template code to write CLR object properties without setter-visibility checks, enabling attackers to modify properties with private, internal, or init-only setters.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can access filtered properties and fields by reusing a TemplateContext after tightening its MemberFilter, bypassing sandbox policies across requests or tenants.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Scriban versions from 3.0.0 through 7.2.5 contain a denial of service vulnerability in the ScriptRange.Multiply operator that bypasses LoopLimit when the left operand is a lazy sequence.
    confidence_band: high
cves:
  - id: CVE-2026-73061
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73061
  - https://github.com/scriban/scriban/security/advisories/GHSA-7jvp-hj45-2f2m
  - https://www.vulncheck.com/advisories/scriban-before-arbitrary-property-write-via-typedobjectaccessor
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74790
  - https://github.com/scriban/scriban/security/advisories/GHSA-5wr9-m6jw-xx44
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73060
  - https://github.com/scriban/scriban/security/advisories/GHSA-89cf-6hmv-8rxm
  - https://www.vulncheck.com/advisories/scriban-through-denial-of-service-via-scriptrange-multiply
  - https://github.com/scriban/scriban/security/advisories/GHSA-6q7j-xr26-3h2c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74783
  - https://www.vulncheck.com/advisories/scriban-through-parser-recursion-denial-of-service
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74787
  - https://github.com/scriban/scriban/security/advisories/GHSA-xcx6-vp38-8hr5
  - https://www.vulncheck.com/advisories/scriban-before-uncontrolled-recursion-via-object-to-json
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74788
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit and update Scriban package dependencies to >= 7.2.2
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-73061 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Restrict user-provided template input
      owner: Application Security
      addresses: CVE-2026-73061
      evidence: Vulnerability allows manipulation of live host objects through template code
updates:
  - at: "2026-08-16T14:25:40Z"
    level: L2
    summary: added coverage for Scriban
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74790
  - at: "2026-08-16T14:26:00Z"
    level: L1
    summary: added coverage for Scriban (3.0.0 through 7.2.5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73060
  - at: "2026-08-16T14:26:11Z"
    level: L1
    summary: added coverage for Scriban (6.6.0-7.2.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74783
  - at: "2026-08-16T14:26:18Z"
    level: L1
    summary: added coverage for Scriban
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74787
  - at: "2026-08-16T14:26:26Z"
    level: L1
    summary: added coverage for Scriban
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74788
---

Scriban, a popular .NET template engine, contains a critical access-modifier bypass vulnerability (CVE-2026-73061) affecting the TypedObjectAccessor component. This flaw occurs in versions prior to 7.2.2 and enables template code to circumvent standard setter-visibility checks. By exploiting this, an attacker can write to CLR object properties that should be protected by private, internal, or init-only modifiers.

The vulnerability is particularly severe because it allows for mass assignment on public-setter properties and the modification of protected object states. In a web application context, an attacker capable of providing or influencing template input can manipulate internal host object states, potentially leading to privilege escalation or unauthorized data modification within the host application. Given the ubiquity of Scriban in .NET-based enterprise applications, organizations using custom template rendering logic are at risk of state manipulation attacks.

## Attack Chain

1. Attacker identifies an endpoint or application feature that accepts user-supplied templates for rendering via Scriban.
2. Attacker crafts a malicious template payload targeting the TypedObjectAccessor functionality.
3. The template engine processes the user-provided input and invokes TypedObjectAccessor to resolve or set properties on the underlying host object.
4. Due to the lack of visibility checks in the vulnerable library, the engine fails to validate if the target property allows external modification.
5. The attacker successfully writes to restricted properties, such as those marked internal or private.
6. The application uses the manipulated object state in subsequent business logic, leading to privilege escalation, bypass of security constraints, or state corruption.
7. The final objective is typically the compromise of application logic or unauthorized modification of data within the application memory space.

## Impact

Successful exploitation allows attackers to bypass property setter constraints, leading to arbitrary property writes. This results in the potential for complete compromise of application state, unauthorized privilege elevation, or data manipulation. Given the nature of template engines in .NET frameworks, the impact is consistent with full application control for the affected process.

## Recommendation

1. Upgrade all instances of the Scriban library to version 7.2.2 or later to remediate CVE-2026-73061.
2. Perform a code audit on all application components that process user-supplied templates using Scriban.
3. Implement strict input validation or sandboxing for any templates sourced from untrusted users to prevent unauthorized access to the underlying .NET object model.
