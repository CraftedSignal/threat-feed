---
title: Stored XSS in Download Monitor WordPress Plugin (CVE-2026-100182)
slug: 2026-10-download-monitor-xss
description: The Download Monitor plugin for WordPress versions up to 5.2.10 is vulnerable to Stored Cross-Site Scripting via a malicious postMessage injection that executes when an administrator interacts with a compromised download object.
date: "2026-10-02T08:23:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:download_monitor:download_monitor:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - cve-2026-100182
vendors:
  - WordPress
products:
  - Download Monitor (<= 5.2.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: This requires the attacker to trick an authenticated Administrator into visiting an attacker-controlled page that targets an open Download edit screen.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-100182
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100182
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Audit and update Download Monitor plugin to a version > 5.2.10.
      owner: IT Operations
      due: 48h
      evidence: Source states all versions up to 5.2.10 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict Content Security Policy (CSP) to restrict script sources.
      owner: IT Operations
      addresses: CVE-2026-100182
      evidence: Stored XSS mitigation strategy
---

The Download Monitor plugin for WordPress, in all versions up to and including 5.2.10, contains a Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-100182). This vulnerability arises from insufficient input sanitization and output escaping when handling Cross-Origin postMessage communications directed at the Admin Editor. An unauthenticated attacker can orchestrate an attack by deceiving an authenticated administrator into visiting an attacker-controlled website while the administrator has an active WordPress Download edit screen open in another tab.

The browser, following the postMessage instructions, triggers the injection of malicious web scripts into the download data. Because the administrator possesses the 'unfiltered_html' capability, WordPress permits the storage of this malicious payload. Once the payload is saved, it is later emitted verbatim to the frontend whenever the [download_data] shortcode is rendered. This allows for unauthorized script execution in the context of victim browsers visiting the compromised site.

## Attack Chain

1. Attacker hosts a malicious website containing an iFrame or script designed to send a crafted cross-origin postMessage.
2. Attacker lures an authenticated WordPress Administrator to visit the malicious website.
3. The malicious website identifies the administrator's session and targets the open WordPress admin panel (e.g., the Download edit screen).
4. The malicious page sends a cross-origin postMessage containing a script payload to the admin panel.
5. The Download Monitor plugin fails to sanitize the incoming postMessage, causing the payload to be injected into the Download edit field.
6. The administrator, having 'unfiltered_html' permissions, saves the download object, causing the malicious script to be persisted in the WordPress database.
7. When a user visits a page containing the [download_data] shortcode, the server renders the payload.
8. The victim's browser executes the script in the context of the WordPress site.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's browser session. This can lead to session hijacking, unauthorized actions performed on behalf of the user, or redirection to further malicious content. All websites running Download Monitor version 5.2.10 or earlier are at risk of this stored XSS, which potentially affects any visitor to the site.

## Recommendation

Update the Download Monitor plugin to the latest patched version immediately (version 5.2.11 or higher is recommended once available). In the absence of an immediate patch, restrict access to the WordPress admin panel via IP allowlisting and monitor access logs for anomalous POST requests to the download management endpoints. Since this is an application-level XSS vulnerability, ensure that Content Security Policy (CSP) headers are strictly configured to prevent the execution of inline scripts and unauthorized external resources.
