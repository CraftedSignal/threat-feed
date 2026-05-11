---
title: MantisBT Stored HTML Injection/XSS Vulnerability in Clone Issue Form (CVE-2026-34463)
slug: 2026-05-mantisbt-xss
description: MantisBT versions 2.28.1 and earlier are vulnerable to stored HTML injection/XSS in the clone issue form, where improper escaping of the source project name allows attackers with manager or administrator access to inject malicious HTML when cloning issues from different projects, although this is mitigated by CSP.
date: "2026-05-11T19:36:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - html-injection
  - mantisbt
  - CVE-2026-34463
vendors:
  - composer
  - MantisBT
products:
  - mantisbt/mantisbt (<= 2.28.1)
  - MantisBT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-fvjf-68wh-rwp2
  - CVE-2026-34463
rules:
  - title: Detect MantisBT Project Name Modification with HTML Injection (CVE-2026-34463)
    description: Detects CVE-2026-34463 exploitation — modification of MantisBT project names to include HTML tags, indicative of potential XSS vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect MantisBT Clone Issue Form Request with HTML in Project Name (CVE-2026-34463)
    description: Detects CVE-2026-34463 exploitation — HTTP request to the MantisBT clone issue form where the project name contains HTML.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

MantisBT versions 2.28.1 and earlier are susceptible to a stored HTML injection/cross-site scripting (XSS) vulnerability in the clone issue form. This flaw arises when cloning an issue from a project different from the current one. The `bug_report_page.php` script prepends the source project's name to the category selector without proper escaping. An attacker with sufficient privileges (typically *manager* or *administrator* level) to modify a project's name can inject arbitrary HTML. This injected HTML is then rendered in the clone issue form, potentially leading to XSS attacks. The vulnerability is identified as CVE-2026-34463. Note that the impact is somewhat mitigated by the presence of Content Security Policy (CSP), which restricts script execution.

## Attack Chain

1. Attacker gains *manager* or *administrator* access to a MantisBT project.
2. Attacker modifies the project name to include malicious HTML, such as `<script>alert('XSS')</script>`.
3. A user views an issue in a different project than the project whose name has been modified.
4. The user attempts to clone the issue using the clone issue form (`bug_report_page.php`).
5. The clone issue form prepends the malicious project name to the category selector without proper escaping.
6. The injected HTML is rendered in the user's browser.
7. If CSP is not properly configured or can be bypassed, the injected script executes, potentially allowing the attacker to steal cookies, redirect the user, or deface the application.
8. The attacker could potentially escalate privileges or gain unauthorized access to sensitive information.

## Impact

Successful exploitation of this vulnerability allows attackers with *manager* or *administrator* privileges to inject arbitrary HTML and potentially execute malicious JavaScript code in the context of other users' browsers. This could lead to session hijacking, defacement of the MantisBT application, or unauthorized access to sensitive information. The impact is mitigated to some extent by the presence of Content Security Policy (CSP), which limits the actions that injected scripts can perform. The number of victims and sectors targeted is dependent on the specific MantisBT instance and its user base.

## Recommendation

*   Upgrade MantisBT to a version later than 2.28.1, which includes the patch `df22697ae497ddd93f3d9132fdf4979db8d081cd` to remediate the vulnerability.
*   As a workaround, ensure that project names in MantisBT do not contain any HTML tags, as mentioned in the advisory.
*   Deploy the Sigma rule "Detect MantisBT Project Name Modification with HTML Injection (CVE-2026-34463)" to detect attempts to inject HTML into project names.
