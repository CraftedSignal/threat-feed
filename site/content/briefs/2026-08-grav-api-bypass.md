---
title: Authentication Scope Bypass in Grav API Plugin Leading to RCE
slug: 2026-08-grav-api-bypass
description: An API key scope-cap bypass in the Grav API plugin allows attackers with restricted keys to execute server-side templates via Server-Side Template Injection.
date: "2026-08-14T14:11:25Z"
lastmod: "2026-08-18T12:53:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - rce
  - ssti
  - grav-cms
  - web-application-vulnerability
  - cve-2026-75829
vendors:
  - getgrav
products:
  - grav-plugin-api (< 1.0.13)
  - grav-plugin-api (< 1.0.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Grav API plugin... contains an API key scope-cap bypass... this allows Twig-in-content to execute server-side, resulting in server-side template injection (SSTI) and remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can submit crafted header and content parameters to execute server-side template injection payloads that are evaluated at render time.
    confidence_band: high
cves:
  - id: CVE-2026-72824
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72824
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75829
  - https://github.com/getgrav/grav/security/advisories/GHSA-w94c-jmg4-w4c9
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav API plugin to 1.0.13
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-72824 patch requirement
  mitigation_plan:
    - priority: immediate
      action: Disable security.twig_content.process_enabled in Grav configuration
      owner: IT Operations
      addresses: CVE-2026-72824
      evidence: Mitigates the SSTI vector described in the source
updates:
  - at: "2026-08-18T12:53:21Z"
    level: L2
    summary: added coverage for grav-plugin-api (< 1.0.15)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75829
---

The Grav API plugin (getgrav/grav-plugin-api) version 1.0.13 and earlier contains a critical authorization vulnerability within the PagesController::guardTwigContent() method. The vulnerability stems from the plugin's failure to validate API key scopes when performing Twig-toggle checks. Specifically, the system utilizes a bare isSuperAdmin() gate instead of consulting the associated api_key_scopes.

This flaw allows an attacker possessing an API key restricted to api.pages.write - provided it was minted on a super account - to override authorization controls and enable process.twig during page save operations. If the target Grav instance has security.twig_content.process_enabled set to true and editor_enabled set to false, an attacker can leverage this bypass to inject arbitrary Twig tags. This leads to Server-Side Template Injection (SSTI), granting the attacker the ability to execute code on the underlying host server. This vulnerability is significant for organizations relying on Grav API for content management as it effectively turns a restricted write operation into full system compromise.

## Impact

The vulnerability results in unauthenticated or low-privilege Remote Code Execution (RCE) on the server hosting Grav CMS. If successfully exploited, an attacker gains the ability to execute arbitrary commands, read sensitive server files, and potentially move laterally within the network. This affects all installations of the Grav API plugin version 1.0.12 and below where the specified Twig processing configurations are active.

## Recommendation

- Upgrade the Grav API plugin to version 1.0.13 or higher immediately to apply the patch for CVE-2026-72824.
- Audit all active API keys in the Grav environment to verify scopes and reduce the number of keys minted on super-administrator accounts.
- Review the configuration file for security.twig_content.process_enabled and ensure it is set to false unless Twig-in-content functionality is strictly required for the business operation.
- Monitor web server logs for HTTP requests directed at the PagesController or save-page endpoints containing unexpected Twig syntax (e.g., {{ ... }} or {% ... %}) in content fields.
