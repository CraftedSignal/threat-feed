---
title: NukeViet Multiple Anti-XSS Filter Bypasses Leading to Stored XSS
slug: 2026-07-nukeviet-xss-bypass
description: Two filter-bypass techniques in NukeViet\Core\Request allow a low-privileged user with news-posting permission to store and execute arbitrary JavaScript in the browsers of any visitor to an affected page, leading to session cookie theft, credential harvesting, defacement, and further privilege escalation via CVE-2026-54064.
date: "2026-07-13T17:58:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - cms
  - cross-site-scripting
  - filter-bypass
vendors:
  - Vinades
products:
  - NukeViet (< 4.6.00)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'allows a low-privileged user (any account with news post permission) to store and serve arbitrary JavaScript to any visitor of the affected page. Proof-of-concept payload (URL-encoded POST body field `bodyhtml`): `<img src="x" %0Conerror="alert(''XSS'')">`'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: This enables session cookie theft, credential harvesting, defacement, and further privilege escalation.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-465g-4q99-5x86
  - https://cwe.mitre.org/data/definitions/79.html
  - https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
  - https://owasp.org/Top10/A03_2021-Injection/
---

A critical vulnerability, CVE-2026-54064, has been identified in NukeViet content management system versions prior to 4.6.00, specifically impacting the `NukeViet\Core\Request` class. This vulnerability allows a low-privileged authenticated user with news-posting permissions to execute stored Cross-Site Scripting (XSS) attacks. Two distinct filter bypass techniques enable attackers to inject arbitrary JavaScript: one involves prefixing HTML event handler attributes with a Form Feed character (`\x0C`) to circumvent `filterAttr()`'s `on` keyword check, and the other utilizes a decimal HTML entity (`&#9;`) for a tab character within `javascript:` URIs to bypass `unhtmlentities()`'s keyword filtering. These bypasses allow malicious scripts to be embedded in news articles, which are then rendered and executed in the browsers of any visitor, including administrators. This can lead to severe consequences such as session hijacking, credential theft, website defacement, and potential full system compromise, underscoring the importance of immediate patching.

## Attack Chain

1. An attacker obtains low-privileged user credentials for a NukeViet instance, with permissions to post or edit news articles.
2. The attacker crafts a malicious payload, such as `<img src="x" %0Conerror="alert('XSS')">`, intending to inject it into a news article's content.
3. Alternatively, the attacker crafts a Markdown-style link containing `jav&#9;ascript:alert('XSS')`, which is designed to bypass NukeViet's input sanitization.
4. The attacker submits the crafted payload as part of the `bodyhtml` field when creating or updating a news article within the NukeViet CMS.
5. NukeViet's backend processing, specifically `NukeViet\Core\Request::filterAttr()` and `NukeViet\Core\Request::unhtmlentities()`, fails to correctly sanitize the input due to the identified filter bypasses.
6. The unsanitized malicious HTML and JavaScript are persistently stored in the NukeViet database.
7. When any user, including an administrator, browses to the affected news article page, their web browser renders the malicious content.
8. The embedded JavaScript executes within the victim's browser context, potentially leading to session cookie theft, credential harvesting, or other malicious actions, ultimately resulting in privilege escalation or further compromise.

## Impact

The successful exploitation of this vulnerability grants an authenticated attacker with news-posting permissions the ability to inject persistent JavaScript into the NukeViet content management system. This JavaScript executes within the browser of any user who views the compromised news article, including highly privileged administrators. The primary consequences include session cookie theft, which can lead to account takeover, and credential harvesting through deceptive forms. Furthermore, attackers could deface the website, redirect users to malicious sites, or leverage the compromised administrator session to achieve further privilege escalation and potentially full control over the NukeViet installation and underlying server. This widespread impact on all visitors, coupled with the potential for administrative account compromise, poses a significant threat to data integrity and system security.

## Recommendation

- Apply the patch by updating NukeViet to version 4.6.00 or higher immediately to address CVE-2026-54064.
- Implement robust web application firewall (WAF) rules to detect and block requests containing known XSS bypass techniques, such as the Form Feed character (`%0C`) within HTML attribute names or decimal HTML entities (`&#9;`) in `javascript:` URIs, specifically referencing the patterns found in CVE-2026-54064.
- Enable comprehensive logging of HTTP request bodies for web servers hosting NukeViet instances, where feasible, to capture full payload data for detection and forensic analysis of XSS attempts related to CVE-2026-54064.
