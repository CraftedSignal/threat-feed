---
title: Stored XSS via Unvalidated URL Scheme in @tinacms/web-components
slug: 2026-10-tinacms-xss
description: The @tinacms/web-components package is vulnerable to stored Cross-Site Scripting (XSS) due to a failure to validate URL schemes in the tina-markdown component, allowing attackers to execute arbitrary code in the browser context of site visitors.
date: "2026-10-09T21:24:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tinacms:web-components:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-components
  - tinacms
vendors:
  - TinaCMS
products:
  - '@tinacms/web-components (<= 0.2.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'An attacker with CMS access can inject javascript: pseudo-protocol URIs, which execute arbitrary code in the browser of any visitor clicking the link.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: 'A link authored in the CMS as javascript: renders as a live javascript: anchor, so a visitor who clicks it executes attacker-supplied script in the site''s origin.'
    confidence_band: high
cves:
  - id: CVE-2026-108260
    cvss: 7.6
references:
  - https://github.com/advisories/GHSA-c42q-qvc3-j6vg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108260
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade @tinacms/web-components to 0.2.1 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies vulnerable component version 0.2.0
  mitigation_plan:
    - priority: immediate
      action: 'Apply strict CSP header to prevent javascript: pseudo-protocol execution'
      owner: Security Engineering
      addresses: CVE-2026-108260
      evidence: Stored XSS via attribute injection
---

The `@tinacms/web-components` package (specifically version 0.2.0 and earlier) contains a high-severity stored Cross-Site Scripting (XSS) vulnerability. The `<tina-markdown>` component is responsible for rendering rich-text content from the TinaCMS content API into the DOM. While other renderers in the TinaCMS ecosystem correctly sanitize URL attributes, this specific component directly assigns the `url` property of link nodes to the `href` attribute of an `<a>` element without any scheme validation. 

An attacker with the ability to edit content within the CMS can supply a `javascript:` pseudo-protocol URL. When a user clicks the resulting link on the published site, the malicious payload executes in the site's origin. This is particularly dangerous as it allows for the theft of sensitive data, such as local storage tokens (e.g., `tinacms-auth`), if the victim is an authenticated editor or administrator.

## Attack Chain

1. Attacker gains access to the TinaCMS administrative interface to edit content fields.
2. Attacker modifies a rich-text field to include a hyperlink targeting a `javascript:` URI.
3. The CMS processes and stores the malicious AST representation of the rich-text.
4. The victim visits the public-facing webpage that utilizes the `<tina-markdown>` web component.
5. The component renders the malicious AST, creating an `<a>` element with the unvalidated `javascript:` payload in the `href` attribute.
6. The victim clicks the hyperlink.
7. The browser executes the JavaScript payload in the site's origin.
8. Attacker script exfiltrates sensitive browser data, such as `localStorage` authentication tokens.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript in the context of the vulnerable site's origin. Impacted sectors include any organization using TinaCMS for web content management. If an authenticated administrator or editor interacts with the malicious link, the attacker can hijack the session, exfiltrate sensitive local storage data, or perform unauthorized actions on behalf of the user, potentially leading to a full account takeover of the CMS instance.

## Recommendation

1. Upgrade `@tinacms/web-components` to a patched version once available that implements URL scheme sanitization.
2. Until a patch is applied, implement a Content Security Policy (CSP) that restricts the usage of `javascript:` URIs in navigation and forbids inline script execution.
3. Utilize the existing `sanitizeUrl` utility from `@tinacms/mdx/sanitize-url` to manually sanitize `node.url` before assignment if patching the library source directly is required.
4. Review content stored in CMS rich-text fields for suspicious `javascript:` schemes.
