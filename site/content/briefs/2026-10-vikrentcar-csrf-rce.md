---
brief_id: brief-2026-10-28-vikrentcar-csrf-rce
event_id: brief-2026-10-28-vikrentcar-csrf-rce
revision: 1
activity_at: "2026-10-28T08:27:40Z"
title: 'VikRentCar Car Rental Management System: Cross-Site Request Forgery RCE (CVE-2026-111120)'
slug: 2026-10-vikrentcar-csrf-rce
description: The VikRentCar plugin for WordPress (<= 1.4.8) contains a CSRF vulnerability in the condtext_update_tmpl function that permits unauthenticated attackers to achieve remote code execution by injecting PHP code into template files.
date: "2026-10-28T08:27:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:vikwp:vikrentcar:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - cms
  - vulnerability
  - rce
vendors:
  - VikWP
products:
  - VikRentCar Car Rental Management System (<= 1.4.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Successful exploitation additionally requires an action by an administrator — the attacker cannot trigger the vulnerability on their own.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to write arbitrary PHP code... achieving remote code execution on the server via a forged request.
    confidence_band: high
cves:
  - id: CVE-2026-111120
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111120
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade VikRentCar plugin to a patched version beyond 1.4.8.
      owner: IT Operations
      due: 48h
      evidence: Source states all versions up to 1.4.8 are vulnerable.
  hunt_leads:
    - lead: Search web server logs for HTTP POST requests to the condtext_update_tmpl function that originate from external IP addresses.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Lack of nonce validation on the condtext_update_tmpl function allows unauthenticated attackers to perform the action.
  mitigation_plan:
    - priority: immediate
      action: Review file integrity of the WordPress installation, specifically looking for changes to template files in the VikRentCar plugin directory.
      owner: IT Operations
      addresses: CVE-2026-111120
      evidence: Attacker writes arbitrary PHP code to the plugin's executable template files.
---

The VikRentCar Car Rental Management System plugin for WordPress is vulnerable to Cross-Site Request Forgery (CSRF) in versions up to and including 1.4.8. The vulnerability exists due to missing or incorrect nonce validation within the `condtext_update_tmpl` function. This flaw allows an unauthenticated attacker to inject arbitrary PHP code into plugin template files, such as `site/helpers/email_tmpl.php`. When these files are subsequently processed by the `loadEmailTemplate()` or `loadPdfTemplate()` functions, the injected code is executed on the server. The vulnerability includes a mechanism where placeholders are expanded and sanitization is reversed, effectively restoring the malicious payload before it is written to the filesystem. Successful exploitation requires an attacker to trick a site administrator into clicking a malicious link.

## Attack Chain

1. Attacker crafts a malicious request targeting the `condtext_update_tmpl` function.
2. Attacker embeds a PHP payload within the request parameters.
3. Attacker tricks a site administrator into performing a CSRF action (e.g., clicking a link) while they are authenticated.
4. The application processes the request, failing to validate a nonce.
5. The plugin logic reverses sanitization (e.g., `cleanPHPSourceCode()`), turning the payload into active PHP code.
6. The plugin writes the malicious PHP code to a template file on the server (e.g., `email_tmpl.php`).
7. The application invokes `loadEmailTemplate()` or `loadPdfTemplate()`, which includes and executes the injected PHP file, resulting in RCE.

## Impact

Successful exploitation results in arbitrary remote code execution on the WordPress server, allowing an attacker to gain full control over the affected site.

## Recommendation

* Update the VikRentCar Car Rental Management System plugin to the latest version that patches CVE-2026-111120.
* Audit plugin template directories for unexpected PHP content or modifications in `site/helpers/`.
* Monitor administrative access logs for unusual requests directed at `condtext_update_tmpl` actions.
