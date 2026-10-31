---
brief_id: brief-2026-10-31-mail-mint-rce
event_id: brief-2026-10-31-mail-mint-rce
revision: 1
activity_at: "2026-10-31T02:05:07Z"
title: 'Mail Mint: Unauthenticated PHP Object Injection (CVE-2026-84753)'
slug: 2026-10-mail-mint-rce
description: Mail Mint versions 1.31.0 and earlier contain an unauthenticated PHP object injection vulnerability in the REST API endpoint /mint-form-submit that allows remote attackers to trigger arbitrary object instantiation.
date: "2026-10-31T02:05:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:wpfunnels:mail_mint:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - php
  - vulnerability
  - rce
vendors:
  - WPFunnels
products:
  - Mail Mint (<= 1.31.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated PHP Object Injection in Mail Mint up to 1.31.0.
    confidence_band: high
cves:
  - id: CVE-2026-84753
    cvss: 9.8
    epss: 0.00564
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84753
  - https://github.com/advisories/GHSA-28vg-wv39-3g8h
  - https://patchstack.com/database/wordpress/plugin/mail-mint/vulnerability/wordpress-mail-mint-plugin-1-31-0-php-object-injection-vulnerability?_s_id=cve
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-84753&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-84753 Exploitation Attempt - POST to /mint-form-submit
    description: Detects potential exploitation attempts of CVE-2026-84753 by monitoring POST requests to the vulnerable Mail Mint REST API endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Mail Mint plugin to version 1.31.1 or later
      owner: IT Operations
      due: 24h
      evidence: Patch version 1.31.1 confirmed by vendor advisory
  hunt_leads:
    - lead: Search web server logs for high frequency POST requests to /?rest_route=/mint-mail/v1/mint-form-submit
      technique_id: T1190
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as the specific entry point for exploitation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mail Mint to 1.31.1
      owner: IT Operations
      addresses: CVE-2026-84753
      evidence: Vendor recommendation
---

Mail Mint versions 1.31.0 and lower contain a critical vulnerability (CVE-2026-84753) involving unauthenticated PHP object injection. The vulnerability exists within the REST API endpoint '/mint-form-submit', where user-supplied contact meta data is passed to the 'maybe_unserialize()' function without proper validation. Attackers can exploit this by submitting crafted serialized PHP objects via POST requests, potentially leading to remote code execution if compatible gadget chains are available in the target environment.

## Attack Chain

1. Attacker identifies a WordPress instance with Mail Mint <= 1.31.0 enabled.
2. Attacker performs a GET request to '/?rest_route=/wp/v2/pages' to retrieve the page slug or nonce required for form submission.
3. Attacker sends an initial POST request to '/mint-mail/v1/mint-form-submit' containing malicious serialized data in the contact meta fields.
4. The plugin's 'FormAction::handle_form_submission' function stores this data as contact meta verbatim.
5. Attacker sends a second POST request targeting the same contact context.
6. The plugin retrieves the meta data via 'ContactModel::get'.
7. The application invokes 'safe_unserialize_meta', which calls 'maybe_unserialize' on the stored malicious payload.
8. PHP instantiates the attacker-provided objects, triggering execution through magic methods (e.g., __wakeup or __destruct).

## Impact

Successful exploitation allows for arbitrary PHP object instantiation. Depending on the available class definitions and gadget chains within the WordPress environment, this can result in remote code execution, unauthorized data modification, or service disruption.

## Recommendation

1. Update the Mail Mint plugin to version 1.31.1 or later immediately.
2. Verify the patch by inspecting the application code to ensure that 'is_serialized()' inputs are rejected and 'allowed_classes' is set to 'false' during unserialization operations.
3. Scan application debug logs (e.g., 'debug.log') for unexpected PHP class name errors indicating failed injection attempts, such as the proof-of-concept witness 'POCWitness84753'.
4. Do not rely solely on WAF signatures; prioritization should be placed on patching the underlying software component.
