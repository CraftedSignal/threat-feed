---
brief_id: brief-2026-10-28-ai-marketing-expert-xss
event_id: brief-2026-10-28-ai-marketing-expert-xss
revision: 1
activity_at: "2026-10-28T06:26:14Z"
title: 'AI Marketing Expert: Stored DOM-Based Cross-Site Scripting (CVE-2026-109999)'
slug: 2026-10-ai-marketing-expert-xss
description: The AI Marketing Expert plugin for WordPress (<= 1.2.8) contains a stored DOM-based XSS vulnerability allowing unauthenticated attackers to execute arbitrary JavaScript in the administrative dashboard.
date: "2026-10-28T06:26:14Z"
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
  validation_status: Source explicitly states vulnerability details and version range.
cpes:
  - cpe:2.3:a:ai_marketing_expert:ai_marketing_expert:*:*:*:*:*:wordpress:*:*
vendors:
  - AI Marketing Expert
products:
  - AI Marketing Expert — AI Email Marketing, AI Content Generator, SEO Analyzer, AI Workflow Automation, Social Media &
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: JavaScript widget auto-poll then delivers it to any administrator who opens wp-admin/index.php
    confidence_band: high
cves:
  - id: CVE-2026-109999
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109999
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update the AI Marketing Expert plugin to a version remediating CVE-2026-109999
      owner: IT Operations
      due: 24h
      evidence: The AI Marketing Expert plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Scripting (XSS) via the name parameter in all versions up to, and including, 1.2.8
  hunt_leads:
    - lead: Identify unauthenticated REST API POST requests directed at the AI Marketing Expert plugin endpoints.
      technique_id: T1059.007
      data_needed:
        - Web server access logs
        - WordPress REST API audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The attacker stores the payload via three unauthenticated REST calls
  mitigation_plan:
    - priority: immediate
      action: Disable the chatbot module in the AI Marketing Expert plugin if updating is not immediately feasible.
      owner: IT Operations
      addresses: CVE-2026-109999
      evidence: Exploitation requires only that the chatbot module is active with at least one configured bot
---

The AI Marketing Expert plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Scripting (XSS) via the 'name' parameter. The flaw stems from insufficient input sanitization and output escaping, allowing unauthenticated attackers to inject malicious scripts. The payload is stored via three unauthenticated REST calls and executes within the context of an administrator session when viewing the wp-admin/index.php dashboard.

## Attack Chain
1. Attacker identifies an installation of the AI Marketing Expert plugin with the chatbot module active.
2. Attacker executes three unauthenticated REST API calls to the target WordPress site.
3. The 'name' parameter is injected with an XSS payload, which is improperly sanitized by the plugin.
4. The malicious payload is persisted in the plugin's chatbot configuration data.
5. An administrator logs into the WordPress dashboard and accesses wp-admin/index.php.
6. The plugin's JavaScript widget auto-poll mechanism retrieves the stored payload.
7. The browser renders the payload, executing the JavaScript in the administrator's security context.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript within the browser session of an authenticated WordPress administrator, potentially resulting in unauthorized administrative actions or data theft.

## Recommendation
- Update the AI Marketing Expert plugin to a version beyond 1.2.8 immediately.
- If a patch is unavailable, disable the chatbot module within the plugin settings to mitigate the exploitation vector.
- Review WordPress REST API logs for anomalous unauthenticated POST requests targeting the plugin's configuration endpoints.
