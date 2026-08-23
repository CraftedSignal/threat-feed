---
title: Multiple Sanitization Bypass Vulnerabilities in justhtml Library
slug: 2026-08-justhtml-xss
description: The justhtml library before version 1.15.0 contains multiple vulnerabilities in URL sanitization, HTML serialization, and Markdown passthrough that allow attackers to inject malicious HTML and JavaScript.
date: "2026-08-23T15:37:25Z"
lastmod: "2026-08-23T17:37:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - injection
  - library-vulnerability
vendors:
  - justhtml
products:
  - justhtml (1.15.0)
  - justhtml (<= 1.11.0)
  - justhtml
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Depending on configuration, an attacker can bypass sanitization to inject active HTML and JavaScript
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: enable attackers to inject malicious HTML and JavaScript via crafted inputs
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The issues... can allow active/dangerous content (e.g., script or style) to survive sanitization.
    confidence_band: high
cves:
  - id: CVE-2026-5388
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5388
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8445
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7808
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4671
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade justhtml library to version 1.15.0 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-5388 advisory states version before 1.15.0 contains security issues
  mitigation_plan:
    - priority: immediate
      action: Review application code for html_passthrough=True and custom sanitization policies
      owner: Detection Engineering
      addresses: CVE-2026-5388
      evidence: Advisory notes custom policies and html_passthrough=True are primary vectors
updates:
  - at: "2026-08-23T15:37:38Z"
    level: L2
    summary: added coverage for justhtml (<= 1.11.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-8445
  - at: "2026-08-23T17:37:31Z"
    level: L2
    summary: added coverage for justhtml
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-7808
  - at: "2026-08-23T17:37:37Z"
    level: L1
    summary: added coverage for justhtml
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-4671
---

The justhtml library, specifically versions prior to 1.15.0, contains critical security flaws within its URL sanitization helpers (clean_url_value and clean_url_in_js_string), HTML serialization logic, and Markdown passthrough functionality. These vulnerabilities enable attackers to bypass sanitization filters and inject active HTML and JavaScript content.

The attack surface is primarily driven by misconfigurations or the use of helper APIs and custom policy pipelines. Attackers can leverage these flaws through techniques such as encoded javascript: pseudo-protocols, malformed relative URLs resolved as remote hosts, and the injection of prohibited elements like &lt;style>, &lt;meta http-equiv=refresh>, and &lt;base href> tags. While default configurations are safer, users relying on custom sanitization policies, programmatic DOM construction, or the html_passthrough=True parameter are at the highest risk. These flaws effectively undermine the security boundary of the library, potentially leading to Stored or Reflected Cross-Site Scripting (XSS) depending on the integration within downstream applications.

## Impact

Successful exploitation of these vulnerabilities allows for the execution of arbitrary JavaScript within the context of a victim's browser session. Depending on the target application's sensitivity, this can lead to session hijacking, unauthorized actions performed on behalf of the user, or the exfiltration of sensitive data. Because this is a library-level flaw, the impact is highly dependent on how the library is utilized within specific web applications and CMS frameworks. Organizations utilizing justhtml for content sanitization or Markdown processing should assess whether their specific implementation utilizes the affected helper APIs or custom policies.

## Recommendation

* Upgrade the justhtml library to version 1.15.0 or later to patch these sanitization flaws.
* Audit applications using the justhtml library, specifically searching for the use of html_passthrough=True or custom sanitization-policy configurations.
* Implement secondary Content Security Policy (CSP) headers to mitigate the impact of potential XSS vulnerabilities in the event of a bypass.
* Review existing integration code to ensure that clean_url_value and clean_url_in_js_string are not being misused in contexts where user input can influence the URL scheme or hostname.
