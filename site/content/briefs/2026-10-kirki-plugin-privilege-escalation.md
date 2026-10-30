---
brief_id: brief-2026-10-27-kirki-plugin-privilege-escalation
event_id: brief-2026-10-27-kirki-plugin-privilege-escalation
revision: 3
activity_at: "2026-10-30T15:32:26Z"
revision_history:
  - revision: 2
    at: "2026-10-27T08:32:51Z"
    checksum: sha256:5e5aa1c79470ed41010abb55f4b52cf181f5ca364e1cd57e35e44d0c29b5b2ea
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-75891&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-10-30T15:32:26Z"
    checksum: sha256:a9cf5cb7cf9826c679882cf436f86d4f5f7c5a8a906971330971a64b10a7519b
    summary: added coverage for Kirki (< 6.4.1)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112347
title: 'Kirki: Privilege escalation via PHP object injection (CVE-2026-75891)'
slug: 2026-10-kirki-plugin-privilege-escalation
description: An authenticated PHP object injection vulnerability in the Kirki WordPress plugin allows attackers with subscriber-level access to escalate privileges to administrator via a POP chain.
date: "2026-10-27T07:49:02Z"
lastmod: "2026-10-30T15:30:34Z"
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
  - cpe:2.3:a:kirki:kirki:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-75891&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - vulnerability
  - php-injection
  - privilege-escalation
  - web-application
  - access-control
  - cve-2026-112347
vendors:
  - Kirki
products:
  - Kirki (<= 6.2.5)
  - Kirki (< 6.4.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to inject a PHP Object. The additional presence of a POP chain allows attackers to overwrite an administrator password and gain administrative access.
    confidence_band: high
cves:
  - id: CVE-2026-75891
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112347
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75891
  - https://sploitus.com/exploit?id=CVE-2026-75891&utm_source=rss&utm_medium=rss
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112347
rules:
  - title: Detects CVE-2026-75891 Exploitation - Suspicious AJAX request to Kirki
    description: Detects potential exploitation of CVE-2026-75891 by monitoring for POST requests to the Kirki AJAX handler containing serialized object syntax.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Check WordPress site inventory for Kirki plugin versions <= 6.2.5
      owner: IT Operations
      due: 24h
      evidence: Vulnerability impacts all versions up to 6.2.5
    - action: Upgrade Kirki plugin to version 6.4.1 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112347 identifies this version as the patch.
  hunt_leads:
    - lead: Identify users with subscriber roles performing AJAX calls to kirki_post_apis
      technique_id: T1068
      data_needed:
        - Web server access logs mapped to authenticated user sessions
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attack is authenticated; monitoring user activity is critical
    - lead: Identify suspicious REST API activity to Kirki endpoints
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability exists in the PUT /wp-json/kirki/v1/pages/{page_id} route.
  mitigation_plan:
    - priority: immediate
      action: Disable the Kirki plugin until a vendor-supplied patch is installed
      owner: IT Operations
      addresses: CVE-2026-75891
      evidence: No current patch specified; disabling is the only immediate mitigation
    - priority: immediate
      action: Patch Kirki plugin to version 6.4.1
      owner: IT Operations
      addresses: CVE-2026-112347
      evidence: NVD advisory for CVE-2026-112347
updates:
  - at: "2026-10-27T08:31:42Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-75891&utm_source=rss&utm_medium=rss
  - at: "2026-10-30T15:30:34Z"
    level: L2
    summary: added coverage for Kirki (< 6.4.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112347
---

The Kirki plugin for WordPress contains a vulnerability in the 'get-single-symbol' branch of the 'kirki_post_apis()' AJAX dispatcher. A missing capability check allows authenticated users with subscriber-level permissions to trigger the deserialization of untrusted input. The availability of a gadget chain (POP chain) enables attackers to overwrite administrator passwords, resulting in full administrative access.

## Attack Chain
1. Attacker obtains authenticated access at the subscriber level.
2. Attacker invokes the 'kirki_post_apis()' AJAX dispatcher.
3. Attacker targets the 'get-single-symbol' branch.
4. Attacker submits crafted, serialized PHP input due to missing capability validation.
5. Application deserializes the input, triggering an embedded POP chain.
6. The POP chain execution results in the modification of administrative credentials.
7. Attacker logs in with the newly set administrative credentials.

## Impact
Successful exploitation allows an authenticated low-privileged user to gain full administrative control over the WordPress site, leading to potential full system compromise, data exfiltration, and unauthorized site configuration changes.

## Recommendation
- Update the Kirki plugin to a version beyond 6.2.5 once a patch is made available by the vendor.
- Audit WordPress user accounts for suspicious privilege changes or unrecognized administrative users.
- Review web server access logs for anomalous POST requests directed at the 'kirki_post_apis()' AJAX handler by low-privileged user accounts.
