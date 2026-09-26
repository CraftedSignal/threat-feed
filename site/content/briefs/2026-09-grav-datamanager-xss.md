---
title: Stored XSS in Grav Data Manager Plugin (CVE-2026-100673)
slug: 2026-09-grav-datamanager-xss
description: An unauthenticated stored cross-site scripting vulnerability in the Grav Data Manager plugin allows attackers to execute malicious JavaScript in the context of an administrator's session.
date: "2026-09-26T15:10:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:datamanager:1.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:getgrav:datamanager:1.4.4:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - xss
  - cms-plugin
vendors:
  - getgrav
products:
  - Grav Data Manager plugin (1.0.1-1.4.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: An unauthenticated visitor who submits a front-end form whose submissions are saved to user/data can store an HTML payload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: An unauthenticated attacker can submit a crafted HTML/JavaScript payload via a front-end form which is then executed.
    confidence_band: high
cves:
  - id: CVE-2026-100673
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100673
rules:
  - title: Detect CVE-2026-100673 Exploitation - Suspicious Payload Submission to Data Manager
    description: Detects potential exploitation attempts of CVE-2026-100673 by identifying common XSS payload patterns submitted via HTTP POST requests to Grav front-end forms.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Grav Data Manager plugin to 1.4.5
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in Data Manager 1.4.5.
  hunt_leads:
    - lead: Search user/data entries for script tags and event handlers
      technique_id: T1189
      data_needed:
        - File system inspection of the Grav data directory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Payload is saved to user/data and rendered in the admin panel.
  mitigation_plan:
    - priority: immediate
      action: Update plugin to 1.4.5
      owner: IT Operations
      addresses: CVE-2026-100673
      evidence: Plugin version 1.4.5 resolves the security flaw.
---

The Grav Data Manager plugin (getgrav/grav-plugin-datamanager) versions 1.0.1 through 1.4.4 contain a stored cross-site scripting (XSS) vulnerability due to improper input sanitization. The vulnerability exists within the item-detail view (admin/templates/partials/item.html.twig), where user-supplied data is rendered using the Twig 'raw' filter without adequate escaping. Furthermore, the use of `striptags('<br>')` is insufficient as PHP's `strip_tags()` function can be bypassed, allowing attackers to inject malicious HTML and JavaScript payloads. An unauthenticated attacker can submit a crafted payload via a front-end form which is subsequently saved to the 'user/data' directory. When an administrator accesses the classic admin panel to view the submitted entry, the payload executes in the context of the administrator's session and origin, potentially exposing sensitive data or allowing unauthorized actions via the administrator's credentials and CSRF tokens. This issue is resolved in Data Manager version 1.4.5.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator viewing the data, leading to full account compromise or unauthorized administrative actions. This affects any site utilizing the vulnerable versions of the Data Manager plugin in the classic Grav admin interface, whereas installations using the Grav 2.0 Admin Next interface remain secure due to proper data escaping.

## Recommendation

Update the Grav Data Manager plugin to version 1.4.5 or later immediately. Given the nature of the vulnerability, review all existing data submissions in the 'user/data' directory for signs of malicious script injection, such as unexpected script tags or HTML attributes.
