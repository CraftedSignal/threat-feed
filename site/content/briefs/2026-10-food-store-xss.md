---
brief_id: brief-2026-10-29-food-store-xss
event_id: brief-2026-10-29-food-store-xss
revision: 1
activity_at: "2026-10-29T05:03:49Z"
title: 'The Food Store WordPress plugin: Stored Cross-Site Scripting (CVE-2026-96669)'
slug: 2026-10-food-store-xss
description: The Food Store - Online Food Delivery & Pickup WordPress plugin version 1.5.5 and earlier contains a stored cross-site scripting vulnerability allowing unauthenticated attackers to inject malicious scripts into administrative panels via the service_type cookie.
date: "2026-10-29T05:03:49Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:the_food_store:online_food_delivery_&_pickup:*:*:*:*:*:wordpress:*:*
vendors:
  - The Food Store
products:
  - The Food Store – Online Food Delivery & Pickup (<= 1.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is seeded unauthenticated by supplying a payload via the ?type= query parameter on the public checkout page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96669
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96669
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Check for versions of The Food Store plugin <= 1.5.5 and patch immediately
      owner: IT Operations
      due: 24h
      evidence: Vulnerability confirmed in versions <= 1.5.5
  hunt_leads:
    - lead: Hunt for anomalous requests to the checkout page containing script tags in the type parameter
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The attack is seeded unauthenticated by supplying a payload via the ?type= query parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade to plugin version > 1.5.5
      owner: IT Operations
      addresses: CVE-2026-96669
      evidence: NVD advisory
---

The Food Store - Online Food Delivery & Pickup plugin for WordPress (versions 1.5.5 and earlier) suffers from a stored cross-site scripting (XSS) vulnerability due to improper input sanitization and output escaping. An unauthenticated attacker can supply a malicious payload through the 'type' query parameter on the public checkout page, which the plugin subsequently writes into the 'service_type' browser cookie. This value is persisted into the order metadata and is executed when an administrator views the order within the WordPress dashboard.

## Attack Chain
1. Attacker navigates to the public checkout page of the vulnerable WordPress site.
2. Attacker appends a malicious XSS payload to the 'type' query parameter (e.g., ?type=&lt;script>alert(1)&lt;/script>).
3. The plugin processes the input and sets the 'service_type' cookie in the user's browser with the malicious payload.
4. The malicious payload is stored in the WordPress database within the order metadata.
5. An administrator accesses the WordPress admin panel to view the order details.
6. The WordPress dashboard renders the order metadata, triggering the execution of the stored malicious script in the administrator's browser context.

## Impact
Successful exploitation allows for the execution of arbitrary JavaScript in the context of an administrator's session. This may lead to unauthorized administrative actions, session hijacking, or further compromise of the WordPress site.

## Recommendation
- Upgrade The Food Store - Online Food Delivery & Pickup plugin to a version released after 1.5.5 that contains the security fix.
- Until a patch is applied, implement a Web Application Firewall (WAF) rule to inspect and block suspicious input in the 'type' query parameter on the checkout page.
- Review WordPress audit logs for unexpected administrative activities or modified order metadata.
