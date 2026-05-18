---
title: Formie Plugin Server-Side Template Injection via Hidden Fields (CVE-2026-45697)
slug: 2026-05-formie-ssti
description: A pre-authenticated server-side template injection vulnerability (CVE-2026-45697) exists in the Hidden fields of the Formie Craft plugin, allowing unauthenticated users to submit crafted values that are evaluated as Twig during submission handling, potentially leading to site compromise.
date: "2026-05-18T17:24:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - server-side template injection
  - code-execution
  - craftcms
  - formie
vendors:
  - Verbb
products:
  - Formie
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Services
references:
  - https://github.com/advisories/GHSA-x7m9-mwc2-g6w2
  - CVE-2026-45697
rules:
  - title: Detect Formie SSTI Attempts via POST Requests
    description: Detects CVE-2026-45697 exploitation — Suspicious POST requests to Formie form submission endpoints containing potential Twig syntax, indicating server-side template injection attempts.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
  - title: Detect Formie SSTI via Hidden Field Injection
    description: Detects CVE-2026-45697 exploitation — Identifies requests where Hidden fields values contain Twig syntax, indicating a server-side template injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
rules_count: 2
---

A server-side template injection vulnerability (CVE-2026-45697) has been identified within the Formie plugin for Craft CMS. The vulnerability resides in the processing of Hidden fields with a "Custom" default value. Unauthenticated users can exploit this by submitting crafted values within these Hidden fields. These values are then processed as Twig templates during form submission handling. Successful exploitation allows for arbitrary code execution within the context of the Craft CMS application, potentially leading to complete site compromise. The vulnerability affects sites using public Formie forms with at least one Hidden field configured with a custom default value. Patched versions are 2.2.20 and 3.1.24.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing Formie form on a Craft CMS website.
2. The attacker analyzes the HTML source of the form to identify any Hidden fields that have a "Custom" default value.
3. The attacker crafts a malicious payload using Twig syntax. This payload can contain arbitrary code intended for execution on the server.
4. The attacker injects the malicious Twig payload into the value of the identified Hidden field.
5. The attacker submits the form to the Craft CMS website.
6. The Formie plugin processes the form submission, including the Hidden field containing the injected Twig payload.
7. The Formie plugin evaluates the "Custom" default value of the Hidden field as a Twig template.
8. The malicious Twig payload is executed on the server, leading to arbitrary code execution and potential site compromise.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary code on the affected Craft CMS website. This can lead to complete compromise of the site, including data theft, defacement, or denial of service. The vulnerability affects sites with public Formie forms that include at least one Hidden field configured with a custom default value. The number of affected sites is currently unknown, but any site using the Formie plugin versions prior to the patched releases (2.2.20 and 3.1.24) are potentially vulnerable.

## Recommendation

*   Immediately upgrade Formie to versions 2.2.20 or 3.1.24 to patch CVE-2026-45697.
*   As an interim measure, remove Hidden fields from public forms or switch the Hidden default away from Custom where feasible as a workaround.
*   Deploy the Sigma rule `Detect Formie SSTI Attempts via POST Requests` to identify potential exploitation attempts.
*   Monitor web server logs for suspicious POST requests targeting Formie form submission endpoints, specifically looking for Twig syntax within form parameters.
