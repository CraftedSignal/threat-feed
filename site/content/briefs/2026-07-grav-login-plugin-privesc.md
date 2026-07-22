---
title: Grav Login Plugin Privilege Escalation (CVE-2026-65603)
slug: 2026-07-grav-login-plugin-privesc
description: A critical privilege escalation vulnerability, CVE-2026-65603, exists in the Grav Login plugin (grav-plugin-login) versions up to and including 3.8.11, allowing an authenticated low-privilege user to exploit a flaw in the `processUserProfile()` handler to bypass privilege stripping and escalate to super-admin, enabling admin panel access, remote code execution, and Twig evaluation.
date: "2026-07-22T12:22:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - web-vulnerability
  - grav
  - cms
vendors:
  - Grav
products:
  - Grav Login plugin (grav-plugin-login) <= 3.8.11
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a low-privilege authenticated user can POST crafted profile form data (e.g. access[admin][super]=true) to escalate to super-admin
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: enabling admin panel access, scheduler abuse (RCE), and Twig evaluation.
    confidence_band: high
cves:
  - id: CVE-2026-65603
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65603
---

The Grav Login plugin, specifically versions up to and including 3.8.11, contains a critical privilege escalation vulnerability identified as CVE-2026-65603. This flaw allows an authenticated low-privilege user to elevate their privileges to super-admin status. The vulnerability resides in the `processUserProfile()` handler, responsible for user profile updates. If a Grav administrator has configured the `plugins.login.user_registration.fields` setting to include 'groups' or 'access' fields, and the default 'regular'/DataUser account backend is in use, the handler fails to sanitize these privilege-related fields from user-submitted form data. Consequently, an attacker can send a crafted POST request, for example, `access[admin][super]=true`, which the system then processes, inadvertently granting them super-admin access. This elevated access enables unauthorized control over the Grav admin panel, allowing for potential remote code execution through scheduler manipulation and Twig template evaluation, posing a significant risk to the integrity and confidentiality of the Grav instance.

## Attack Chain

1. An attacker gains initial access to a Grav system with a valid, low-privilege authenticated user account.
2. The attacker identifies that the Grav Login plugin (versions <= 3.8.11) is installed and that the administrator has configured the `plugins.login.user_registration.fields` to include 'groups' and/or 'access' fields.
3. The attacker crafts an HTTP POST request designed to update their user profile via the `processUserProfile()` handler.
4. The crafted POST request's form data includes malicious privilege-escalation parameters, such as `access[admin][super]=true`.
5. The `processUserProfile()` handler processes this request but fails to strip the sensitive 'groups' or 'access' fields from the user-supplied data, unlike the registration handler.
6. The system updates the attacker's user profile with the elevated privileges specified in the crafted request.
7. The attacker's low-privilege account is successfully escalated to super-admin status.
8. With super-admin access, the attacker can now access the Grav admin panel and perform further malicious actions, including remote code execution via scheduler abuse or Twig template evaluation.

## Impact

Successful exploitation of CVE-2026-65603 grants an authenticated low-privilege user super-admin access to the Grav content management system. This enables complete control over the Grav instance, allowing the attacker to modify site content, manage users, and potentially achieve remote code execution (RCE) by abusing the scheduler or evaluating Twig templates. The compromise can lead to full system takeover, data exfiltration, defacement, or persistent unauthorized access, severely impacting the integrity, confidentiality, and availability of the affected Grav environment and any hosted applications or data.

## Recommendation

* Patch CVE-2026-65603 by upgrading the Grav Login plugin (grav-plugin-login) to version 3.8.12 or higher immediately.
* Review the Grav configuration for `plugins.login.user_registration.fields` to ensure that 'groups' and 'access' fields are not inadvertently exposed or enabled for user registration if not strictly required, even after patching.
