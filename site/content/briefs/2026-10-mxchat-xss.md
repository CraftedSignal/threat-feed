---
brief_id: brief-2026-10-28-mxchat-xss
event_id: brief-2026-10-28-mxchat-xss
revision: 1
activity_at: "2026-10-28T08:27:24Z"
title: 'MxChat: Stored DOM-Based Cross-Site Scripting (CVE-2026-110662)'
slug: 2026-10-mxchat-xss
description: The MxChat AI Chatbot plugin for WordPress is vulnerable to unauthenticated stored DOM-based XSS, allowing script injection via the feedback parameter that executes in an administrator's session.
date: "2026-10-28T08:27:24Z"
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
  validation_status: Source verified, rule defined based on described injection vector.
cpes:
  - cpe:2.3:a:mxchat:mxchat_-_ai_chatbot_&_content_generation_for_wordpress:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - MxChat
products:
  - MxChat – AI Chatbot & Content Generation for WordPress (<= 3.2.25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The stored payload is written by any unauthenticated visitor... and detonates automatically when any administrator next loads the Transcripts page.
    confidence_band: high
cves:
  - id: CVE-2026-110662
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110662
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade MxChat - AI Chatbot & Content Generation for WordPress to the latest version.
      owner: IT Operations
      due: 48h
      evidence: Vulnerable in versions <= 3.2.25.
  hunt_leads:
    - lead: Hunt for anomalous POST requests to /wp-admin/admin-ajax.php followed by administrative access to the plugin Transcripts page.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The stored payload is written by any unauthenticated visitor via a single POST to admin-ajax.php.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to version > 3.2.25.
      owner: IT Operations
      addresses: CVE-2026-110662
      evidence: Source states versions up to 3.2.25 are affected.
---

The MxChat - AI Chatbot & Content Generation for WordPress plugin is vulnerable to stored DOM-based Cross-Site Scripting (XSS) in versions up to and including 3.2.25. The flaw exists due to insufficient sanitization and output escaping of the 'feedback' parameter. An unauthenticated attacker can submit a malicious script via a POST request to the plugin's endpoint, which is then stored and executed when an administrator views the plugin's Transcripts page.

## Attack Chain

1. Attacker crafts a malicious payload containing arbitrary JavaScript.
2. Attacker sends an unauthenticated HTTP POST request to the 'admin-ajax.php' endpoint.
3. The plugin accepts and stores the payload within the 'feedback' parameter.
4. An administrator navigates to the Transcripts page within the WordPress dashboard.
5. The plugin renders the stored payload in the administrator's browser.
6. Malicious script executes in the context of the administrator's session.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser session of a logged-in administrator, potentially leading to unauthorized administrative actions, session hijacking, or site-wide configuration changes.

## Recommendation

- Upgrade the MxChat - AI Chatbot & Content Generation for WordPress plugin to a version beyond 3.2.25 immediately.
- If an update is unavailable, disable the plugin until a patch is applied.
- Audit the 'Transcripts' page for unexpected or suspicious content, such as script tags or unconventional data within the feedback logs.
