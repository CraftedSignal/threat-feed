---
title: Anonymous GitHub Vulnerable to XSS via Unsanitized GitHub Repository Content
slug: 2024-01-03-anonymous-github-xss
description: The @tdurieux/anonymous_github application is vulnerable to cross-site scripting (XSS) because it renders unsanitized content from GitHub repositories, allowing a malicious GitHub repository to execute arbitrary JavaScript in the Anonymous GitHub origin.
date: "2026-05-05T18:28:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - github
  - unsanitized-input
  - client-side-vulnerability
vendors:
  - GitHub
products:
  - github.com
  - '@tdurieux/anonymous_github (vulnerable: = 2.2.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-g485-8j3v-p6x8
rules:
  - title: Detect Anonymous GitHub XSS via Unsanitized Markdown
    description: Detects XSS attempts in Anonymous GitHub by identifying unsanitized HTML tags within the rendered README content.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AngularJS $sce Bypass
    description: Detects attempts to bypass AngularJS's $sce context by identifying calls to trustAsHtml.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The @tdurieux/anonymous_github application is vulnerable to cross-site scripting (XSS) due to its unsafe handling of GitHub repository content. Specifically, the application fetches README files from GitHub repositories and renders them without proper sanitization. The vulnerability lies in the client-side rendering process, where markdown is parsed using `marked` with the `sanitize: false` option and then injected into the DOM via `$sce.trustAsHtml()` and `ng-bind-html`, effectively bypassing AngularJS's built-in XSS protection. An attacker can exploit this vulnerability by creating a malicious GitHub repository containing a specially crafted README file that executes arbitrary JavaScript code within the context of the Anonymous GitHub origin. This issue affects version 2.2.0 of @tdurieux/anonymous_github.

## Attack Chain

1.  Attacker creates a malicious GitHub repository.
2.  The attacker crafts a `README.md` file within the repository containing malicious JavaScript embedded within HTML tags, such as `<img src=x onerror="alert(document.domain)">`.
3.  A user navigates to the Anonymous GitHub application.
4.  The user enters the URL of the attacker's malicious repository into Anonymous GitHub to anonymize it.
5.  Anonymous GitHub fetches the `README.md` file from the attacker's repository via GitHub's REST API.
6.  The application renders the `README.md` using `marked` with `sanitize: false` and injects the resulting HTML into the DOM via `$sce.trustAsHtml()` and `ng-bind-html` without sanitization.
7.  The embedded JavaScript within the `README.md` executes in the user's browser within the Anonymous GitHub origin.
8.  The attacker can then steal authentication tokens and session cookies or access other users' anonymization configurations and private repository data.

## Impact

Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary JavaScript code within the Anonymous GitHub origin. This can lead to several critical impacts, including account takeover through stealing authentication tokens and session cookies. Additionally, the attacker could potentially exfiltrate sensitive data, such as other users' anonymization configurations and private repository data via the `/api/user` and `/api/repo/list` endpoints. The application is vulnerable to Stored XSS.

## Recommendation

*   Implement proper sanitization of markdown output using DOMPurify before rendering, leveraging the existing but unused dependency.
*   Modify the server configuration to serve HTML files with the `Content-Disposition: attachment` header or render them within a sandboxed iframe on a separate origin to prevent XSS.
*   Replace the usage of `$sce.trustAsHtml()` with proper `ngSanitize` usage for safe HTML binding in AngularJS.
*   Apply the following remediation steps outlined in the advisory: HTML-escape filenames and paths in directory listing templates, and add Content Security Policy headers.
*   Deploy the Sigma rule "Detect Anonymous GitHub XSS via Unsanitized Markdown" to detect potential exploitation attempts.
