---
brief_id: brief-2026-11-06-elex-plugin-rce
event_id: brief-2026-11-06-elex-plugin-rce
revision: 2
activity_at: "2026-11-06T14:39:33Z"
revision_history:
  - revision: 2
    at: "2026-11-06T14:39:33Z"
    checksum: sha256:199cc205b4d2949e626b07474531f0d80f741739c8eea9aba121c9b60993874b
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=A1F650BA-C05A-59A0-BD55-A4DD63AE4464&utm_source=rss&utm_medium=rss
title: 'ELEX WordPress HelpDesk & Customer Ticketing System: Arbitrary file deletion (CVE-2026-114630)'
slug: 2026-11-elex-plugin-rce
description: The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress contains an arbitrary file deletion vulnerability in the factory_reset function that allows unauthenticated attackers to delete critical system files, potentially leading to remote code execution.
date: "2026-11-06T13:11:27Z"
lastmod: "2026-11-06T14:38:58Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:elex:wordpress_helpdesk_&_customer_ticketing_system:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=A1F650BA-C05A-59A0-BD55-A4DD63AE4464&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - vulnerability
  - wordpress
  - file-deletion
vendors:
  - ELEX
products:
  - ELEX WordPress HelpDesk & Customer Ticketing System (<= 3.3.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'This vulnerability is exploitable via a two-step chain: an unauthenticated attacker first stores an arbitrary ticket_attachment_path value.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1565.001
    technique_name: Stored Data Manipulation
    evidence: causing unlink() to be called on the attacker-supplied path.
    confidence_band: high
cves:
  - id: CVE-2026-114630
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114630
  - https://sploitus.com/exploit?id=A1F650BA-C05A-59A0-BD55-A4DD63AE4464&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Potential Exploitation of CVE-2026-114630
    description: Detects exploitation attempts against the ELEX WordPress HelpDesk & Customer Ticketing System plugin by monitoring for suspicious access to the factory_reset admin page and the associated AJAX ticket submission endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch ELEX WordPress HelpDesk & Customer Ticketing System plugin to the version after 3.3.8
      owner: IT Operations
      due: 24h
      evidence: Vulnerable in all versions up to, and including, 3.3.8
  hunt_leads:
    - lead: Inspect web server logs for HTTP requests directed at the wsdesk_factory_reset page originating from unauthenticated sessions or suspicious IP addresses.
      technique_id: T1190
      data_needed:
        - Webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker triggers the factory_reset routine via a GET request to wp-admin/admin.php?page=wsdesk_factory_reset
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to latest patched release
      owner: IT Operations
      addresses: CVE-2026-114630
      evidence: Vulnerable in versions <= 3.3.8
updates:
  - at: "2026-11-06T14:38:58Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=A1F650BA-C05A-59A0-BD55-A4DD63AE4464&utm_source=rss&utm_medium=rss
---

The ELEX WordPress HelpDesk & Customer Ticketing System plugin is vulnerable to arbitrary file deletion in all versions up to and including 3.3.8. The vulnerability exists within the factory_reset function, which fails to perform proper capability checks, relying instead on the insecure is_admin() request-type check. Unauthenticated attackers can exploit this to delete arbitrary files, such as wp-config.php, by manipulating the ticket_attachment_path.

## Attack Chain

1. Attacker harvests the required AJAX nonce from the [wsdesk_support] shortcode on a public-facing page.
2. Attacker submits a POST request to the eh_crm_new_ticket_post AJAX endpoint.
3. Attacker injects a malicious file path into the ticket_attachment_path parameter during the ticket submission.
4. Attacker performs a GET request to wp-admin/admin.php?page=wsdesk_factory_reset.
5. The factory_reset routine executes due to insufficient authorization checks.
6. The application performs an unlink() operation on the attacker-supplied file path.

## Impact

Successful exploitation allows unauthenticated attackers to delete arbitrary files on the WordPress server. This can lead to a complete site compromise or remote code execution by removing critical configuration files such as wp-config.php, which forces the site back into an installation state.

## Recommendation

- Update the ELEX WordPress HelpDesk & Customer Ticketing System plugin to the latest version.
- Audit existing ticket attachments and recent plugin configuration changes for signs of malicious input.
- Implement access controls for sensitive administrative functions within the WordPress environment.
