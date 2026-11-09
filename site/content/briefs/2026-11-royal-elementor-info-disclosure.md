---
brief_id: brief-2026-11-09-royal-elementor-info-disclosure
event_id: brief-2026-11-09-royal-elementor-info-disclosure
revision: 1
activity_at: "2026-11-09T16:09:10Z"
title: 'WP Royal Elementor Addons: Information disclosure vulnerability'
slug: 2026-11-royal-elementor-info-disclosure
description: A remote, authenticated attacker can exploit a vulnerability in the Royal Elementor Addons plugin for WordPress to gain unauthorized access to sensitive information.
date: "2026-11-09T16:09:10Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation.
tags:
  - wordpress
  - information-disclosure
  - plugin-vulnerability
vendors:
  - WP Royal
products:
  - Royal Elementor Addons
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A remote, authenticated attacker can exploit a vulnerability in WP Royal Royal Elementor Addons to gain unauthorized access to sensitive information.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4392
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory Royal Elementor Addons instances across WordPress sites.
      owner: IT Operations
      due: 7d
      evidence: Vulnerability affects Royal Elementor Addons.
  hunt_leads:
    - lead: Monitor web server access logs for anomalous, high-frequency GET or POST requests directed at plugin-specific API endpoints from authenticated users.
      technique_id: T1592
      data_needed:
        - Web server access logs (Apache/Nginx/IIS)
        - WordPress authentication logs
      priority: low
      confidence: low
      disposition: monitor_or_close
      evidence: Vulnerability requires remote, authenticated access to the plugin.
---

The Royal Elementor Addons plugin for WordPress is affected by an information disclosure vulnerability. A remote, authenticated attacker can leverage this flaw to access information that should otherwise be restricted. This vulnerability requires the attacker to have an active, authenticated session within the WordPress environment.

## Recommendation

- Audit WordPress plugin installations and identify all instances of "Royal Elementor Addons".
- Ensure the plugin is updated to the latest available version provided by WP Royal to incorporate any security fixes.
- Review WordPress access logs to identify authenticated user activity associated with suspicious plugin endpoint requests.
