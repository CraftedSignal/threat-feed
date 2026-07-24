---
title: Microweber CMS Server-Side Template Injection Leads to RCE (CVE-2026-65693)
slug: 2026-07-microweber-ssti
description: An authenticated administrator in Microweber CMS through version 2.0.20 is vulnerable to server-side template injection due to an unsandboxed Twig environment, allowing for arbitrary OS command execution by injecting malicious Twig expressions into mail templates, which are executed automatically upon mail dispatch and can compromise the underlying server.
date: "2026-07-24T16:24:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - server-side-template-injection
  - rce
  - cms
  - web-application
  - microweber
vendors:
  - Microweber
products:
  - Microweber CMS through 2.0.20
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows authenticated administrators to achieve arbitrary OS command execution by injecting Twig expressions
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: causing automatic payload execution on each subsequent application event that triggers a mail dispatch, leading to compromise of the underlying server.
    confidence_band: med
cves:
  - id: CVE-2026-65693
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65693
---

CVE-2026-65693 identifies a critical server-side template injection (SSTI) vulnerability affecting Microweber CMS versions up to 2.0.20. The flaw allows an authenticated administrator to achieve arbitrary operating system command execution (RCE). This vulnerability stems from an unsandboxed Twig environment within the `TwigView::render()` function, which lacks proper security policies such as `SandboxExtension` or `SecurityPolicy`. Attackers can exploit this by injecting malicious Twig expressions, specifically those utilizing `filter('system')`, into mail template bodies. These malicious expressions are stored unsanitized in the database and are automatically executed whenever an application event triggers a mail dispatch, leading to a compromise of the underlying server. This vulnerability presents a significant risk to organizations using affected Microweber CMS instances, as it allows a privileged attacker to gain full control over the host system.

## Attack Chain

1. An attacker gains authenticated administrative access to the Microweber CMS instance, potentially through compromised credentials or other means.
2. The attacker navigates to the mail template editing section within the CMS administration panel.
3. The attacker crafts a malicious Twig expression, such as `{{ T(filter('system')('command_to_execute')) }}`, which leverages the unsandboxed `filter('system')` function to perform OS command execution.
4. The malicious Twig expression is injected by the attacker into a mail template body, which the CMS then stores unsanitized in its backend database.
5. At a later point, an application event occurs that triggers the dispatch of a mail using the compromised template. This could be a user registration, a password reset, or any other event that involves sending an email.
6. During the mail dispatch process, the vulnerable `TwigView::render()` function attempts to render the template. The unsandboxed Twig environment processes the malicious `filter('system')` expression.
7. The `filter('system')` function executes the embedded operating system command with the privileges of the web server process, leading to arbitrary OS command execution on the underlying server.
8. The attacker can then use the executed command to establish further persistence, exfiltrate data, or completely compromise the host system.

## Impact

Successful exploitation of CVE-2026-65693 grants an authenticated administrator arbitrary operating system command execution on the server hosting the Microweber CMS. This allows attackers to take full control of the server, leading to severe consequences such as data theft, defacement of the website, installation of malware, establishment of backdoors, or use of the compromised server as a platform for further attacks. The vulnerability affects Microweber CMS through version 2.0.20, impacting potentially numerous organizations globally that use this platform. The compromise of administrator credentials is a prerequisite, highlighting the importance of robust authentication and least privilege principles.

## Recommendation

* Patch CVE-2026-65693 by updating Microweber CMS to a version beyond 2.0.20 immediately.
* Implement strong authentication measures, such as multi-factor authentication (MFA), for all administrative accounts to mitigate the risk of initial administrative access.
* Monitor web server logs for HTTP POST requests to administrative endpoints that may contain unusual or suspicious template content, particularly strings like "filter('system')".
* Implement file integrity monitoring on critical Microweber CMS files and database tables to detect unauthorized modifications, especially to mail templates.
