---
title: 'n8n: Stored DOM XSS via Resource Locator `cachedResultUrl`'
slug: 2026-07-n8n-stored-dom-xss
description: A stored DOM XSS vulnerability in n8n's Resource Locator feature allows attackers to inject malicious JavaScript into the cachedResultUrl parameter. When a victim opens a specially crafted workflow and interacts with external links, the JavaScript payload executes in their browser, due to a lack of scheme validation for `cachedResultUrl` passed to `window.open()`.
date: "2026-07-22T18:02:15Z"
lastmod: "2026-07-22T18:06:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - vulnerability
  - n8n
vendors:
  - n8n GmbH
  - n8n
products:
  - n8n (< 1.123.64)
  - n8n (>= 2.0.0-rc.0, < 2.29.8)
  - n8n (>= 2.30.0, < 2.30.1)
  - n8n (< 2.29.8)
  - n8n (< 2.30.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: When a victim opens the crafted workflow and interact with external links, the JavaScript payload runs in the victim's browser.
    confidence_band: high
cves:
  - id: CVE-2026-65592
references:
  - https://github.com/advisories/GHSA-9wcp-9r3j-383q
  - https://github.com/advisories/GHSA-h5xr-fqvj-253p
updates:
  - at: "2026-07-22T18:06:12Z"
    level: L1
    summary: new product
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-h5xr-fqvj-253p
---

A high-severity stored DOM XSS vulnerability, identified as CVE-2026-65592, exists in the n8n workflow automation platform's Resource Locator feature. This flaw affects versions prior to 1.123.64, versions 2.0.0-rc.0 through 2.29.7, and version 2.30.0. Attackers can exploit this by injecting malicious JavaScript into the `cachedResultUrl` parameter within a crafted workflow. The vulnerability stems from a lack of scheme validation when `cachedResultUrl` is passed to `window.open()`. When a victim opens such a workflow and interacts with external links, the injected JavaScript executes in their browser. This allows for potential session hijacking, data exfiltration, or further client-side compromise, making it critical for defenders to prioritize upgrading to patched versions.

## Attack Chain

1. An attacker gains authenticated access to an n8n instance with privileges to create or edit workflows.
2. The attacker crafts a malicious JavaScript payload and embeds it within the `cachedResultUrl` parameter of an n8n workflow.
3. The attacker saves the specially crafted workflow onto the vulnerable n8n instance.
4. A victim user opens the compromised workflow in their browser, loading the malicious `cachedResultUrl` value into the DOM.
5. The victim interacts with an external link within the workflow, triggering the `window.open()` function that uses the unvalidated `cachedResultUrl`.
6. The embedded JavaScript payload executes within the victim's browser context, bypassing same-origin policies.
7. The attacker's script performs actions such as session hijacking, data exfiltration, or further client-side exploitation.

## Impact

Successful exploitation of CVE-2026-65592 allows an attacker to execute arbitrary JavaScript within a victim's browser context. This can lead to various severe consequences, including session hijacking, unauthorized access to the victim's n8n account, data exfiltration of sensitive information displayed in the n8n interface, or further client-side exploitation through drive-by downloads or credential harvesting. While no specific victim numbers are provided, any user interacting with a compromised workflow could be affected, posing a significant risk to organizations using vulnerable n8n instances. The primary impact is on the confidentiality and integrity of user data within the affected n8n instance.

## Recommendation

Immediately patch n8n instances to versions 1.123.64, 2.29.8, 2.30.1, or later to address CVE-2026-65592. As a temporary mitigation, restrict workflow creation and editing permissions in n8n to only trusted users. Implement application-level auditing to identify workflows containing unexpected `cachedResultUrl` values with non-HTTP(S) schemes, as detailed in the workarounds section of the advisory for CVE-2026-65592.
