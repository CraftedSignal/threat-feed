---
title: 'CVE-2026-24425: Twig Sandbox Bypass Vulnerability'
slug: 2026-05-twig-sandbox-bypass
description: Twig versions 2.16.x and 3.9.0 through 3.25.x contain a sandbox bypass vulnerability (CVE-2026-24425) when using a SourcePolicyInterface, allowing attackers to pass arbitrary PHP callables and execute arbitrary code when the sandbox is enabled through a source policy rather than globally.
date: "2026-05-20T14:17:58Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - twig
  - sandbox-bypass
  - code-execution
  - cve-2026-24425
vendors:
  - Twigphp
products:
  - Twig (2.16.x)
  - Twig (3.9.0 through 3.25.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-24425
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24425
  - https://github.com/twigphp/Twig/releases/tag/v3.26.0
  - https://github.com/twigphp/Twig/security/advisories/GHSA-2q52-x2ff-qgfr
  - https://www.vulncheck.com/advisories/twig-x-x-sandbox-bypass-via-sourcepolicyinterface
rules:
  - title: Detect Twig Sandbox Bypass Attempt via PHP Callable
    description: Detects CVE-2026-24425 exploitation — an attempt to bypass the Twig sandbox by using a PHP callable function within Twig template filters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detect Twig SourcePolicyInterface Usage
    description: Detects usage of SourcePolicyInterface which is required to exploit CVE-2026-24425
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

Twig, a flexible template engine for PHP, is susceptible to a sandbox bypass vulnerability identified as CVE-2026-24425. This flaw affects versions 2.16.x and 3.9.0 through 3.25.x. The vulnerability resides within the SourcePolicyInterface, which is intended to enforce security restrictions on template execution. However, a flaw in the runtime check allows attackers with template rendering capabilities to circumvent these restrictions. Specifically, attackers can pass arbitrary PHP callables to `sort`, `filter`, `map`, and `reduce` filters, leading to arbitrary code execution if the sandbox is enabled via a source policy. This bypass occurs because the runtime check fails to use the current template source, allowing malicious code to be injected and executed.

## Attack Chain

1. An attacker gains the ability to render Twig templates, often through a web application vulnerability such as template injection.
2. The application uses a SourcePolicyInterface to enable a security sandbox for Twig templates.
3. The attacker crafts a malicious Twig template that leverages the `sort`, `filter`, `map`, or `reduce` filters.
4. Within these filters, the attacker provides an arbitrary PHP callable function.
5. The vulnerable runtime check fails to properly validate the source of the template.
6. The arbitrary PHP callable is executed without proper sandbox restrictions.
7. The attacker achieves arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows attackers with template rendering capabilities to bypass the intended security sandbox and execute arbitrary code on the server. This can lead to complete system compromise, data theft, or denial of service. While the specific number of affected installations is unknown, any application using Twig within the specified version range and relying on SourcePolicyInterface for sandboxing is potentially vulnerable.

## Recommendation

*   Upgrade Twig to version 3.26.0 or later, which contains a fix for CVE-2026-24425.
*   If upgrading is not immediately feasible, avoid using SourcePolicyInterface for sandboxing and rely on global sandbox settings instead.
*   Monitor web server logs for suspicious activity related to template rendering, particularly the use of `sort`, `filter`, `map`, and `reduce` filters.
*   Deploy the Sigma rule "Detect Twig Sandbox Bypass Attempt via PHP Callable" to identify potential exploitation attempts in web server logs.
