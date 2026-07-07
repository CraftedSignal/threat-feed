---
title: Formie Hidden Field SSTI Vulnerability (CVE-2026-52889)
slug: 2026-07-formie-ssti
description: Formie Hidden fields in versions prior to 3.1.27 are vulnerable to Server-Side Template Injection (SSTI), allowing an unauthenticated attacker to inject Twig syntax into request-derived default values, potentially leading to remote code execution, sensitive information disclosure, or application state modification.
date: "2026-07-06T17:01:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - server-side-template-injection
  - web-vulnerability
  - craft-cms
  - formie
  - rce
  - cve-2026-52889
  - network
vendors:
  - Verbb
products:
  - Formie (< 3.1.27)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker could trigger server-side template evaluation by visiting a public form containing a Hidden field configured with a request-derived default value.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allowed an unauthenticated attacker to provide Twig syntax in request-controlled input and have it evaluated server-side when the form was rendered.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-565m-g33j-jq96
rules:
  - title: Detects CVE-2026-52889 Exploitation — Formie SSTI via Request-Derived Hidden Fields
    description: Detects CVE-2026-52889 exploitation — attempts to inject Twig template syntax into HTTP request headers (User-Agent, Referer, Cookie) or query parameters, targeting Formie Hidden fields in Craft CMS.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.009
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical Server-Side Template Injection (SSTI) vulnerability, tracked as CVE-2026-52889, has been discovered in the `verbb/formie` plugin for Craft CMS. This flaw affects versions `3.0.0-beta.1` up to `3.1.26` and allows an unauthenticated attacker to execute arbitrary code or disclose sensitive information. The vulnerability arises when a public-facing form contains a Hidden field configured with a dynamic, request-derived default value (e.g., HTTP User Agent, Referer URL, Current URL, Query Parameter, or Cookie Value). Attackers can inject malicious Twig templating syntax into these request fields, which is then evaluated server-side during front-end form rendering. This could lead to a complete compromise of the affected Craft CMS instance, exposing data, modifying application state, or enabling remote code execution, making immediate patching crucial for defenders.

## Attack Chain

1.  Attacker identifies a Craft CMS instance utilizing the vulnerable Formie plugin (versions >= 3.0.0-beta.1 and <= 3.1.26).
2.  Attacker scans for public-facing forms on the target instance that contain a Hidden field configured to use a request-derived default value (e.g., HTTP User Agent, Referer URL, Query Parameter, or Cookie Value).
3.  Attacker crafts a specially malformed HTTP request targeting the identified form.
4.  The malicious request embeds Twig template syntax within the value of the request-derived field (e.g., `User-Agent: {{_self.env.getconfig()}}` or `?param={{7*7}}`).
5.  The Formie plugin, specifically within the `Hidden::getFrontEndInputOptions()` function, copies the attacker-controlled input directly into the `defaultValue` for the Hidden field.
6.  During the subsequent front-end rendering process of the form, Craft CMS's Twig rendering engine evaluates the malicious `defaultValue` server-side, executing the injected Twig syntax.
7.  Successful exploitation results in Server-Side Template Injection, potentially leading to remote code execution, disclosure of sensitive application or system information, or unauthorized modification of application state.

## Impact

Successful exploitation of CVE-2026-52889 allows an unauthenticated attacker to trigger server-side template evaluation simply by visiting a crafted URL. Depending on the injected payload and the site's Craft CMS configuration, this can lead to severe consequences including arbitrary remote code execution on the server hosting the Craft CMS instance. Other potential impacts include the disclosure of sensitive application data, database credentials, or system configurations, and unauthorized modification of the application's state, potentially defacing websites or disrupting services. The unauthenticated nature of the vulnerability means any public-facing vulnerable form is at risk.

## Recommendation

*   Immediately update `verbb/formie` to version `3.1.27` or later to patch CVE-2026-52889.
*   As a temporary workaround until patching, audit all public forms and remove or reconfigure any Hidden fields using request-derived default values, specifically: HTTP User Agent, HTTP Refer URL, Current URL, Current URL without Query String, Query Parameter, or Cookie Value, as noted in the summary.
*   Deploy the provided Sigma rule "Detects CVE-2026-52889 Exploitation — Formie SSTI via Request-Derived Hidden Fields" to your SIEM/detection platform and tune it for your environment to identify attempted exploitation.
