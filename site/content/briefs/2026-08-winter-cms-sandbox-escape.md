---
title: Winter CMS Twig Sandbox Escape Vulnerability
slug: 2026-08-winter-cms-sandbox-escape
description: Authenticated backend users with template-editing privileges can bypass the Winter CMS Twig sandbox to execute arbitrary PHP or SQL, stemming from an incomplete fix for CVE-2024-54149.
date: "2026-08-20T19:12:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wintercms:winter:*:*:*:*:*:*:*:*
vendors:
  - Winter CMS
products:
  - Winter CMS (1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Using any of the following permissions, an attacker can... achieve remote code execution by injecting PHP into a CMS page, layout, or partial code section.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The sandbox could be bypassed through... saveQuietly()/deleteQuietly(), increment()/decrement(), newQuery(), getConnection().
    confidence_band: high
cves:
  - id: CVE-2024-54149
    cvss: 8.4
    epss: 0.00405
references:
  - https://github.com/advisories/GHSA-8cfw-pcwh-v63w
  - https://github.com/wintercms/winter/commit/725bbcda232466f7f71381c271c6916573d576e6
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - System Administration
  immediate_actions:
    - action: Upgrade Winter CMS to v1.2.13
      owner: IT Operations
      due: 24h
      evidence: Fixed in v1.2.13
  mitigation_plan:
    - priority: immediate
      action: Restrict CMS template editing permissions to trusted users
      owner: System Administration
      addresses: cms.manage_pages, cms.manage_layouts, cms.manage_partials
      evidence: Advisory recommends restricting permissions as interim mitigation
---

Winter CMS contains a sandbox escape vulnerability within its Twig template security policy, resulting from an incomplete fix for CVE-2024-54149. This vulnerability allows authenticated backend users possessing specific CMS template-editing permissions (cms.manage_pages, cms.manage_layouts, or cms.manage_partials) to escape the Twig "safe mode" sandbox. The flaw exists because the existing security blocklist in System\Twig\SecurityPolicy failed to account for recursive method forwarding in Eloquent models and query builders. By leveraging methods like saveQuietly, increment, or getConnection, an attacker can manipulate database records, execute arbitrary SQL, or achieve remote code execution by injecting PHP into CMS templates. The issue is addressed in Winter CMS v1.2.13.

## Impact

Successful exploitation allows an authenticated user to escalate privileges or gain remote code execution within the context of the web application. Attackers can perform unauthorized database operations, including dropping tables, modifying administrative credentials, or executing arbitrary system-level code if the server configuration permits. This affects all users running vulnerable versions of the system module prior to v1.2.13.

## Recommendation

* Upgrade to Winter CMS v1.2.13 or later immediately to patch the SecurityPolicy logic.
* Clear the compiled Twig template cache using "php artisan cache:clear" after upgrading to ensure the new security policy is applied to existing templates.
* Audit and restrict administrative permissions for "cms.manage_pages", "cms.manage_layouts", and "cms.manage_partials" to trusted users only, as these are prerequisites for exploiting this vulnerability.
