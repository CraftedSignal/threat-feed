---
title: EasyAdmin Bundle Stored Cross-Site Scripting via File Uploads (CVE-2026-54087)
slug: 2026-07-easyadmin-xss
description: A high-severity stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-54087, exists in EasyAdmin Bundle versions >= 5.0.0 and < 5.0.13, allowing attackers to upload malicious HTML or SVG files containing JavaScript which executes in an administrator's session when viewed in the backend, leading to session/CSRF token theft and privilege escalation.
date: "2026-07-14T20:25:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-application
  - vulnerability
  - easyadmin
vendors:
  - EasyCorp
products:
  - EasyAdmin Bundle (versions >= 5.0.0, < 5.0.13)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: When another user opens it from the backend, it is served from the same origin and the script executes in the context of their authenticated admin session.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8559-gwj3-q37r
---

A significant stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-54087, impacts EasyAdmin Bundle versions 5.0.0 through 5.0.12. This flaw arises when the `FileField` and `ImageField` components are misconfigured to store uploaded files within the public web root. By default, `FileField` lacks MIME or extension restrictions, and `ImageField` accepts SVG files, both of which can embed browser-executable JavaScript. An attacker with access to a form using these fields can upload a malicious `.html` or `.svg` file containing JavaScript. When a legitimate administrator subsequently views this uploaded file within the EasyAdmin backend, the embedded script executes in the context of their authenticated session. This can lead to the theft of session tokens or CSRF tokens, ultimately resulting in privilege escalation. This vulnerability does not permit remote code execution (RCE) because EasyAdmin's filename handling prevents the upload of `.php` or `.phtml` files.

## Attack Chain

1. A developer configures an EasyAdmin application with `FileField` or `ImageField` components to store uploaded files within the public web root directory.
2. An attacker gains access to an EasyAdmin form that utilizes these configured `FileField` or `ImageField` components, typically as a low-privileged user.
3. The attacker crafts a malicious file, either an `.html` file for `FileField` or an `.svg` file for `ImageField`, embedding JavaScript code designed for session theft or privilege escalation.
4. The attacker uploads the malicious file through the vulnerable EasyAdmin form.
5. EasyAdmin stores the malicious file in the publicly accessible web directory as per the misconfiguration.
6. A high-privileged administrator later accesses the EasyAdmin backend and attempts to view the uploaded file through the interface.
7. The administrator's web browser fetches the malicious file, which is served inline from the application's domain, and executes the embedded JavaScript due to the browser's same-origin policy.
8. The executed JavaScript steals the administrator's session cookies or CSRF tokens, or performs other actions, enabling unauthorized privilege escalation or further malicious activities within the administrator's authenticated context.

## Impact

Successful exploitation of CVE-2026-54087 can lead to severe consequences for the compromised EasyAdmin instance. Attackers can leverage the executed JavaScript to steal authenticated user sessions, including those of high-privileged administrators. This stolen session information can then be used to perform unauthorized actions, including data manipulation, configuration changes, or further compromise of the system by exploiting the administrator's privileges. Additionally, CSRF tokens can be exfiltrated, enabling cross-site request forgery attacks against the system. The primary impact is the unauthorized access and privilege escalation within the web application, although remote code execution is not directly achievable through this specific vulnerability. The impact relies on developers configuring file uploads to a publicly accessible web directory and a privilege gap between the uploading user and the viewing administrator.

## Recommendation

* **Patch CVE-2026-54087**: Immediately upgrade EasyAdmin Bundle to version 5.0.13 or newer to remediate CVE-2026-54087.
* **Review File Upload Configurations**: Review all `FileField` and `ImageField` configurations within your EasyAdmin applications to ensure uploaded files are NOT stored in public web-accessible directories or are served with `Content-Disposition: attachment` headers to prevent inline execution.
* **Implement Strict Content Security Policy (CSP)**: Deploy or strengthen Content Security Policies (CSPs) on your web servers to restrict script execution sources, thereby mitigating the impact of potential XSS vulnerabilities even if malicious files are uploaded and viewed.
