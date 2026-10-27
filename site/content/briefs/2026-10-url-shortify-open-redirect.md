---
brief_id: brief-2026-10-27-url-shortify-open-redirect
event_id: brief-2026-10-27-url-shortify-open-redirect
revision: 1
activity_at: "2026-10-27T18:15:41Z"
title: 'KaizenCoders URL Shortify: Unauthenticated Open Redirect (CVE-2026-1277)'
slug: 2026-10-url-shortify-open-redirect
description: CVE-2026-1277 is an unauthenticated open redirect vulnerability in the URL Shortify WordPress plugin that allows attackers to redirect users to malicious websites via a crafted redirect_to parameter.
date: "2026-10-27T18:15:41Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kaizencoders:url_shortify:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - open-redirect
  - web-application
  - cve-2026-1277
vendors:
  - KaizenCoders
products:
  - URL Shortify (< 1.12.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.001
    subtechnique_name: Malicious Link
    evidence: The victim must click a crafted link.
    confidence_band: high
cves:
  - id: CVE-2026-1277
    cvss: 4.7
    epss: 0.00658
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=6F6F79AB-D794-5C99-8818-CC718379859C
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1277
  - https://sploitus.com/exploit?id=6F6F79AB-D794-5C99-8818-CC718379859C&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-1277 Exploitation Attempt
    description: Detects HTTP requests to admin-ajax.php containing the redirect_to parameter targeting external domains, which may indicate exploitation of the open redirect vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1204.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade URL Shortify to version 1.12.2 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor patch recommendation
  hunt_leads:
    - lead: Search web logs for requests to wp-admin/admin-ajax.php containing the redirect_to parameter
      technique_id: T1204.001
      data_needed:
        - Web access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The PoC uses this endpoint to facilitate the open redirect.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.12.2
      owner: IT Operations
      addresses: CVE-2026-1277
      evidence: Plugin patched in 1.12.2
---

CVE-2026-1277 is an unauthenticated open redirect vulnerability affecting the URL Shortify WordPress plugin (versions prior to 1.12.2). The vulnerability resides in the `handle_promotions` method within `url-shortify/lite/includes/Promo.php`. While the plugin sanitizes the `redirect_to` parameter using `esc_url_raw()`, it fails to validate the destination against a whitelist, enabling arbitrary redirection to external domains. A public proof-of-concept (PoC) exploit has been released, enabling attackers to generate malicious URLs that facilitate phishing campaigns by abusing trust in the target site.

## Attack Chain

1. Attacker crafts a malicious URL pointing to the site's `admin-ajax.php` endpoint.
2. Attacker injects a target phishing domain into the `redirect_to` parameter.
3. Attacker distributes the link to a victim via social engineering.
4. Victim clicks the malicious link while interacting with the legitimate WordPress site.
5. WordPress server processes the request and executes `wp_redirect` using the attacker-supplied parameter.
6. Victim is redirected to the attacker-controlled phishing site.

## Impact

Successful exploitation allows an attacker to abuse a trusted domain to redirect users to malicious, phishing, or malware-hosting sites. This vulnerability does not allow server-side compromise or unauthorized access to the underlying WordPress instance.

## Recommendation

1. Upgrade the URL Shortify plugin to version 1.12.2 or later immediately.
2. If an immediate update is not possible, deactivate the plugin until the patch can be applied.
3. Implement WAF rules to reject requests to `admin-ajax.php` where the `redirect_to` parameter contains external hostnames that do not match an allow-list of your domain.
