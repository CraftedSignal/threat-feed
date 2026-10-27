---
brief_id: brief-2026-10-27-membershipworks-info-disclosure
event_id: brief-2026-10-27-membershipworks-info-disclosure
revision: 1
activity_at: "2026-10-27T22:06:40Z"
title: 'MembershipWorks WordPress Plugin: Information Disclosure (CVE-2026-112355)'
slug: 2026-10-membershipworks-info-disclosure
description: The MembershipWorks WordPress plugin prior to version 6.17 fails to enforce content protection filters on WordPress REST API requests, allowing unauthenticated attackers to retrieve restricted member-only content.
date: "2026-10-27T22:06:40Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:membershipworks:membershipworks:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - information-disclosure
  - rest-api
vendors:
  - MembershipWorks
products:
  - MembershipWorks (< 6.17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The plugin fails to apply content protection filters to requests processed via the WordPress REST API, allowing unauthenticated attackers to access and retrieve member-only content.
    confidence_band: high
cves:
  - id: CVE-2026-112355
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112355
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade the MembershipWorks plugin to version 6.17 or later across all WordPress instances.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112355 vulnerability advisory for MembershipWorks
  hunt_leads:
    - lead: Monitor WordPress access logs for high-volume or repeated REST API requests originating from unauthorized IP addresses, specifically targeting endpoints that return page or post content.
      technique_id: T1592
      data_needed:
        - WordPress web server access logs (e.g., cs-uri-stem containing /wp-json/wp/v2/posts or /wp-json/wp/v2/pages)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows unauthenticated access to restricted content via the WordPress REST API.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to MembershipWorks 6.17 or later
      owner: IT Operations
      addresses: CVE-2026-112355
      evidence: NVD advisory indicates vulnerability is resolved in 6.17
---

The MembershipWorks WordPress plugin (versions prior to 6.17) contains an information disclosure vulnerability (CVE-2026-112355). The vulnerability exists because the plugin's access control logic - which restricts sensitive content - is only applied during standard front-end page rendering. It is not attached to the WordPress REST API, allowing unauthorized users to retrieve protected content by querying the REST API endpoint directly.

## Impact

Unauthenticated remote attackers can bypass content restrictions and access private data intended exclusively for registered members. No exploit code or evidence of in-the-wild exploitation is currently documented.

## Recommendation

* Update the MembershipWorks plugin to version 6.17 or later immediately.
* Review WordPress access logs for anomalous REST API traffic targeting post or page content if the plugin was previously exposed to public internet traffic.
